#include "vnsl/sim/j1939_node.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include "vnsl/j1939/id.hpp"

namespace vnsl::sim {
namespace {

constexpr std::uint32_t kPgnAck = 0xE800;  // 59392 Acknowledgment
constexpr std::uint8_t kCtrlRts = 16;
constexpr std::uint8_t kCtrlCts = 17;
constexpr std::uint8_t kCtrlEndOfMsgAck = 19;
constexpr std::uint8_t kCtrlBam = 32;
constexpr std::uint8_t kCtrlAbort = 255;
constexpr std::uint8_t kAbortTimeout = 3;

std::uint8_t b0(std::uint32_t v) { return static_cast<std::uint8_t>(v & 0xFF); }
std::uint8_t b1(std::uint32_t v) { return static_cast<std::uint8_t>((v >> 8) & 0xFF); }
std::uint8_t b2(std::uint32_t v) { return static_cast<std::uint8_t>((v >> 16) & 0xFF); }

std::uint32_t pgn_at(const can::Frame& f, std::size_t i) {
    return static_cast<std::uint32_t>(f.data[i]) | (static_cast<std::uint32_t>(f.data[i + 1]) << 8) |
           (static_cast<std::uint32_t>(f.data[i + 2]) << 16);
}

std::array<std::uint8_t, 8> name_bytes(std::uint64_t name) {
    std::array<std::uint8_t, 8> b{};
    for (std::size_t i = 0; i < 8; ++i) b[i] = static_cast<std::uint8_t>(name >> (8 * i));
    return b;
}

}  // namespace

J1939Node::J1939Node(std::string label, std::uint64_t name, std::uint8_t preferred_address, bool arbitrary_capable)
    : label_(std::move(label)), name_(name), preferred_(preferred_address), arbitrary_capable_(arbitrary_capable) {}

void J1939Node::transmit_frame(Simulator& sim, std::uint8_t priority, std::uint32_t pgn, std::uint8_t sa,
                               std::uint8_t da, std::span<const std::uint8_t> data) {
    can::Frame f;
    f.extended = true;
    f.id = j1939::encode_id(priority, pgn, sa, da);
    f.dlc = static_cast<std::uint8_t>(std::min<std::size_t>(data.size(), 8));
    std::copy_n(data.begin(), f.dlc, f.data.begin());
    sim.transmit(*this, f);
    ++stats_.frames_sent;
}

int J1939Node::timer_after(Simulator& sim, std::uint64_t delay_us, std::function<void()> action) {
    const int id = next_internal_--;
    internal_timers_.emplace(id, std::move(action));
    sim.schedule(*this, sim.now() + delay_us, id);
    return id;
}

void J1939Node::cancel(int timer_id) { internal_timers_.erase(timer_id); }

void J1939Node::schedule_app(Simulator& sim, std::uint64_t at_us, int id) {
    if (id >= 0) sim.schedule(*this, at_us, id);
}

void J1939Node::on_timer(Simulator& sim, int timer_id) {
    if (timer_id >= 0) {
        on_app_timer(sim, timer_id);
        return;
    }
    const auto it = internal_timers_.find(timer_id);
    if (it == internal_timers_.end()) return;  // cancelled
    auto action = std::move(it->second);
    internal_timers_.erase(it);
    action();
}

// ---- Address claim ---------------------------------------------------------------------

void J1939Node::start(Simulator& sim) {
    const auto power_up = [this, &sim] {
        address_ = preferred_;
        state_ = ClaimState::Claiming;
        send_claim(sim);
    };
    if (start_delay_us_ == 0) {
        power_up();
    } else {
        timer_after(sim, start_delay_us_, power_up);
    }
}

void J1939Node::send_claim(Simulator& sim) {
    const auto bytes = name_bytes(name_);
    transmit_frame(sim, 6, j1939::kPgnAddressClaimed, address_, j1939::kGlobalAddress, bytes);
    ++stats_.claims_sent;
    if (state_ == ClaimState::Claiming) {
        const std::uint8_t claimed = address_;
        timer_after(sim, kClaimWaitUs, [this, &sim, claimed] {
            if (state_ == ClaimState::Claiming && address_ == claimed) {
                state_ = ClaimState::Claimed;
                on_claimed(sim);
            }
        });
    }
}

void J1939Node::send_cannot_claim(Simulator& sim) {
    const auto bytes = name_bytes(name_);
    transmit_frame(sim, 6, j1939::kPgnAddressClaimed, j1939::kNullAddress, j1939::kGlobalAddress, bytes);
}

std::uint8_t J1939Node::pick_free_address() const {
    for (unsigned a = 128; a <= 247; ++a) {
        const auto addr = static_cast<std::uint8_t>(a);
        if (addr != address_ && !seen_claims_.contains(addr)) return addr;
    }
    return j1939::kNullAddress;
}

void J1939Node::handle_claim(Simulator& sim, std::uint8_t sa, std::uint64_t other) {
    if (sa == j1939::kNullAddress) return;  // a Cannot Claim
    seen_claims_[sa] = other;
    const bool active = state_ == ClaimState::Claiming || state_ == ClaimState::Claimed;
    if (!active || sa != address_ || other == name_) return;
    if (other > name_) {  // ours is the lower NAME, so it has priority: defend the address
        ++stats_.claims_defended;
        send_claim(sim);
        return;
    }
    ++stats_.claims_lost;
    bam_queue_.clear();
    cmdt_queue_.clear();
    const std::uint8_t next = arbitrary_capable_ ? pick_free_address() : j1939::kNullAddress;
    if (next == j1939::kNullAddress) {
        state_ = ClaimState::CannotClaim;
        address_ = j1939::kNullAddress;
        send_cannot_claim(sim);
        return;
    }
    address_ = next;
    state_ = ClaimState::Claiming;
    send_claim(sim);
}

// ---- Receiving -------------------------------------------------------------------------

void J1939Node::on_frame(Simulator& sim, const can::Frame& frame) {
    if (!frame.extended) return;
    const j1939::Id id = j1939::decode_id(frame.id);
    reassembler_.on_frame(frame, [&](const j1939::Message& m) {
        const bool for_me = m.da == j1939::kGlobalAddress || (address_ != j1939::kNullAddress && m.da == address_);
        if (!for_me) return;
        if (m.pgn == j1939::kPgnAddressClaimed && m.data.size() >= 8) {
            std::uint64_t other = 0;
            for (std::size_t i = 8; i-- > 0;) other = (other << 8) | m.data[i];
            handle_claim(sim, m.sa, other);
            return;
        }
        if (m.pgn == j1939::kPgnRequest) {
            handle_request(sim, m);
            return;
        }
        if (m.multipacket && m.da == address_) {
            const auto packets = (m.data.size() + 6) / 7;
            send_cm(sim, m.sa,
                    {kCtrlEndOfMsgAck, b0(static_cast<std::uint32_t>(m.data.size())),
                     b1(static_cast<std::uint32_t>(m.data.size())), static_cast<std::uint8_t>(packets), 0xFF,
                     b0(m.pgn), b1(m.pgn), b2(m.pgn)});
            ++stats_.cmdt_received;
        }
        if (state_ == ClaimState::Claimed) on_message(sim, m);
    });

    if (address_ == j1939::kNullAddress || id.da != address_) return;
    if (id.pgn == j1939::kPgnTpConnection && frame.dlc == 8) {
        handle_tp_cm(sim, frame, id.sa, id.da);
    } else if (id.pgn == j1939::kPgnTpDataTransfer && frame.dlc == 8) {
        // Grant the next batch once the current one has arrived.
        const std::size_t seq = frame.data[0];
        const auto it = std::find_if(cmdt_receive_.begin(), cmdt_receive_.end(),
                                     [&](const auto& r) { return r.peer == id.sa; });
        if (it != cmdt_receive_.end() && seq == it->batch_end) {
            if (seq >= it->packets) {
                cmdt_receive_.erase(it);
            } else {
                const std::size_t count = std::min(kMaxPacketsPerCts, it->packets - seq);
                it->batch_end = seq + count;
                send_cm(sim, id.sa,
                        {kCtrlCts, static_cast<std::uint8_t>(count), static_cast<std::uint8_t>(seq + 1), 0xFF, 0xFF,
                         b0(it->pgn), b1(it->pgn), b2(it->pgn)});
            }
        }
    }
}

void J1939Node::handle_tp_cm(Simulator& sim, const can::Frame& frame, std::uint8_t sa, std::uint8_t /*da*/) {
    const std::uint8_t control = frame.data[0];
    const std::uint32_t pgn = pgn_at(frame, 5);
    if (control == kCtrlRts) {
        const std::size_t size = static_cast<std::size_t>(frame.data[1]) | (static_cast<std::size_t>(frame.data[2]) << 8);
        const std::size_t packets = frame.data[3];
        if (size < 9 || size > j1939::Reassembler::kMaxPayload || packets != (size + 6) / 7) return;
        std::erase_if(cmdt_receive_, [&](const auto& r) { return r.peer == sa; });
        const std::size_t limit = frame.data[4] == 0xFF ? kMaxPacketsPerCts : std::min<std::size_t>(frame.data[4], kMaxPacketsPerCts);
        const std::size_t count = std::min(std::max<std::size_t>(limit, 1), packets);
        cmdt_receive_.push_back({sa, pgn, packets, count});
        send_cm(sim, sa, {kCtrlCts, static_cast<std::uint8_t>(count), 1, 0xFF, 0xFF, b0(pgn), b1(pgn), b2(pgn)});
        return;
    }
    if (!cmdt_ || cmdt_->msg.da != sa || cmdt_->msg.pgn != pgn) return;
    auto& s = *cmdt_;
    if (control == kCtrlCts) {
        cancel(s.timer);
        const std::size_t count = frame.data[1];
        const std::size_t next = frame.data[2];
        if (count > 0 && next >= 1 && next <= s.packets) {
            const std::size_t last = std::min(s.packets, next + count - 1);
            for (std::size_t seq = next; seq <= last; ++seq) send_dt(sim, s.msg, seq, s.msg.da);
        }
        s.timer = timer_after(sim, kT3Us, [this, &sim] { cmdt_timeout(sim); });
    } else if (control == kCtrlEndOfMsgAck) {
        cancel(s.timer);
        ++stats_.cmdt_sent;
        cmdt_.reset();
        start_next_cmdt(sim);
    } else if (control == kCtrlAbort) {
        cancel(s.timer);
        ++stats_.cmdt_failed;
        cmdt_.reset();
        start_next_cmdt(sim);
    }
}

void J1939Node::handle_request(Simulator& sim, const j1939::Message& m) {
    if (m.data.size() < 3) return;
    const std::uint32_t pgn = static_cast<std::uint32_t>(m.data[0]) | (static_cast<std::uint32_t>(m.data[1]) << 8) |
                              (static_cast<std::uint32_t>(m.data[2]) << 16);
    const bool to_me = m.da == address_;
    if (pgn == j1939::kPgnAddressClaimed) {
        if (state_ == ClaimState::Claiming || state_ == ClaimState::Claimed) send_claim(sim);
        if (state_ == ClaimState::CannotClaim) send_cannot_claim(sim);
        return;
    }
    if (state_ != ClaimState::Claimed) return;
    const auto payload = on_request(sim, pgn, m.sa);
    if (!payload) {
        if (to_me) {  // negative acknowledgement, to the global address with the requester inside
            const std::array<std::uint8_t, 8> nack{1, 0xFF, 0xFF, 0xFF, m.sa, b0(pgn), b1(pgn), b2(pgn)};
            transmit_frame(sim, 6, kPgnAck, address_, j1939::kGlobalAddress, nack);
            ++stats_.nacks_sent;
        }
        return;
    }
    ++stats_.requests_answered;
    const bool pdu1 = ((pgn >> 8) & 0xFF) < 240;
    // A specific request is answered to the requester (point to point when it needs transport);
    // a global one to everyone. A single-frame PDU2 group is always broadcast.
    std::uint8_t da = to_me ? m.sa : j1939::kGlobalAddress;
    if (payload->size() <= 8 && !pdu1) da = j1939::kGlobalAddress;
    send(sim, 6, pgn, da, *payload);
}

// ---- Sending ---------------------------------------------------------------------------

void J1939Node::send(Simulator& sim, std::uint8_t priority, std::uint32_t pgn, std::uint8_t da,
                     std::span<const std::uint8_t> data) {
    if (state_ != ClaimState::Claimed || data.size() > j1939::Reassembler::kMaxPayload) return;
    if (data.size() <= 8) {
        transmit_frame(sim, priority, pgn, address_, da, data);
        return;
    }
    Outgoing o{priority, pgn, da, std::vector<std::uint8_t>(data.begin(), data.end())};
    if (da == j1939::kGlobalAddress) {
        bam_queue_.push_back(std::move(o));
        start_next_bam(sim);
    } else {
        cmdt_queue_.push_back(std::move(o));
        start_next_cmdt(sim);
    }
}

void J1939Node::send_cm(Simulator& sim, std::uint8_t da, std::array<std::uint8_t, 8> bytes) {
    transmit_frame(sim, 7, j1939::kPgnTpConnection, address_, da, bytes);
}

void J1939Node::send_dt(Simulator& sim, const Outgoing& msg, std::size_t seq, std::uint8_t da) {
    std::array<std::uint8_t, 8> b{};
    b.fill(0xFF);
    b[0] = static_cast<std::uint8_t>(seq);
    for (std::size_t i = 0; i < 7; ++i) {
        const std::size_t k = (seq - 1) * 7 + i;
        if (k < msg.data.size()) b[1 + i] = msg.data[k];
    }
    transmit_frame(sim, 7, j1939::kPgnTpDataTransfer, address_, da, b);
}

void J1939Node::start_next_bam(Simulator& sim) {
    if (bam_ || bam_queue_.empty()) return;
    Sending s;
    s.msg = std::move(bam_queue_.front());
    bam_queue_.pop_front();
    s.packets = (s.msg.data.size() + 6) / 7;
    const auto size = static_cast<std::uint32_t>(s.msg.data.size());
    send_cm(sim, j1939::kGlobalAddress,
            {kCtrlBam, b0(size), b1(size), static_cast<std::uint8_t>(s.packets), 0xFF, b0(s.msg.pgn), b1(s.msg.pgn),
             b2(s.msg.pgn)});
    bam_ = std::move(s);
    // One packet every 50 ms (J1939-21 allows 50 to 200 ms).
    bam_->timer = timer_after(sim, kBamGapUs, [this, &sim] { bam_step(sim); });
}

void J1939Node::bam_step(Simulator& sim) {
    if (!bam_) return;
    send_dt(sim, bam_->msg, bam_->next, j1939::kGlobalAddress);
    if (++bam_->next > bam_->packets) {
        ++stats_.bam_sent;
        bam_.reset();
        start_next_bam(sim);
        return;
    }
    bam_->timer = timer_after(sim, kBamGapUs, [this, &sim] { bam_step(sim); });
}

void J1939Node::start_next_cmdt(Simulator& sim) {
    if (cmdt_ || cmdt_queue_.empty()) return;
    Sending s;
    s.msg = std::move(cmdt_queue_.front());
    cmdt_queue_.pop_front();
    s.packets = (s.msg.data.size() + 6) / 7;
    const auto size = static_cast<std::uint32_t>(s.msg.data.size());
    send_cm(sim, s.msg.da,
            {kCtrlRts, b0(size), b1(size), static_cast<std::uint8_t>(s.packets), 0xFF, b0(s.msg.pgn), b1(s.msg.pgn),
             b2(s.msg.pgn)});
    cmdt_ = std::move(s);
    cmdt_->timer = timer_after(sim, kT3Us, [this, &sim] { cmdt_timeout(sim); });
}

// The receiver went quiet: abort the connection (reason 3, timeout) and move on.
void J1939Node::cmdt_timeout(Simulator& sim) {
    if (!cmdt_) return;
    const std::uint32_t pgn = cmdt_->msg.pgn;
    send_cm(sim, cmdt_->msg.da, {kCtrlAbort, kAbortTimeout, 0xFF, 0xFF, 0xFF, b0(pgn), b1(pgn), b2(pgn)});
    ++stats_.cmdt_failed;
    cmdt_.reset();
    start_next_cmdt(sim);
}

}  // namespace vnsl::sim
