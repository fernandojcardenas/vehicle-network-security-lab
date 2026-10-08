#include "vnsl/j1939/transport.hpp"

#include <algorithm>

namespace vnsl::j1939 {
namespace {

constexpr std::uint8_t kCtrlRts = 16;
constexpr std::uint8_t kCtrlCts = 17;
constexpr std::uint8_t kCtrlEndOfMsgAck = 19;
constexpr std::uint8_t kCtrlBam = 32;
constexpr std::uint8_t kCtrlAbort = 255;

std::uint32_t embedded_pgn(const can::Frame& f) {
    return static_cast<std::uint32_t>(f.data[5]) | (static_cast<std::uint32_t>(f.data[6]) << 8) |
           (static_cast<std::uint32_t>(f.data[7]) << 16);
}

std::size_t announced_size(const can::Frame& f) {
    return static_cast<std::size_t>(f.data[1]) | (static_cast<std::size_t>(f.data[2]) << 8);
}

/// A transfer announcement is believable only if every number in it agrees.
bool valid_announcement(std::size_t size, std::size_t packets, std::uint32_t pgn) {
    if (size < 9 || size > Reassembler::kMaxPayload) return false;  // 0..8 bytes fit in one frame
    if (packets != (size + 6) / 7) return false;
    if (pgn > 0x3FFFF) return false;
    // A PDU1 PGN's low byte (the destination) is always 0 inside a PGN field.
    if (((pgn >> 8) & 0xFF) < 240 && (pgn & 0xFF) != 0) return false;
    return pgn != kPgnTpConnection && pgn != kPgnTpDataTransfer;  // no transport inside transport
}

}  // namespace

void Reassembler::on_frame(const can::Frame& frame, const Sink& sink) {
    ++stats_.frames;
    if (!frame.extended) {
        ++stats_.ignored_non_j1939;
        return;
    }
    expire(frame.t_us);
    const Id id = decode_id(frame.id);
    if (id.pgn == kPgnTpConnection) {
        on_connection(frame, id);
        return;
    }
    if (id.pgn == kPgnTpDataTransfer) {
        on_data(frame, id, sink);
        return;
    }
    ++stats_.single_frame_messages;
    Message m;
    m.t_us = frame.t_us;
    m.priority = id.priority;
    m.pgn = id.pgn;
    m.sa = id.sa;
    m.da = id.da;
    const auto payload = frame.payload();
    m.data.assign(payload.begin(), payload.end());
    sink(m);
}

void Reassembler::expire(std::uint64_t now_us) {
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        const auto& s = it->second;
        const std::uint64_t timeout = s.broadcast ? limits_.bam_packet_timeout_us : limits_.cmdt_timeout_us;
        if (now_us > s.last_us && now_us - s.last_us > timeout) {
            ++stats_.timeouts;
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

void Reassembler::start_session(const Key& key, Session session) {
    auto it = sessions_.find(key);
    if (it != sessions_.end()) {
        ++stats_.replaced_sessions;
        it->second = std::move(session);
        return;
    }
    if (sessions_.size() >= limits_.max_sessions) {
        ++stats_.rejected_too_many_sessions;
        return;
    }
    sessions_.emplace(key, std::move(session));
}

void Reassembler::on_connection(const can::Frame& frame, const Id& id) {
    if (frame.dlc != 8) {
        ++stats_.malformed_tp_frames;
        return;
    }
    const std::uint8_t control = frame.data[0];
    const std::uint32_t pgn = embedded_pgn(frame);
    switch (control) {
        case kCtrlBam:
        case kCtrlRts: {
            const bool broadcast = control == kCtrlBam;
            const std::size_t size = announced_size(frame);
            const std::size_t packets = frame.data[3];
            // BAM goes to everyone; RTS opens a connection with one node, never the global address.
            const bool right_destination = broadcast == (id.da == kGlobalAddress);
            if (!right_destination || !valid_announcement(size, packets, pgn)) {
                ++stats_.bad_announcements;
                return;
            }
            Session s;
            s.broadcast = broadcast;
            s.priority = id.priority;
            s.pgn = pgn;
            s.size = size;
            s.packets = packets;
            s.last_us = frame.t_us;
            s.data.reserve(size);
            if (broadcast) {
                ++stats_.bam_started;
            } else {
                ++stats_.rts_started;
            }
            start_session({id.sa, id.da}, std::move(s));
            return;
        }
        case kCtrlCts: {
            ++stats_.cts;
            // CTS travels from the receiver back to the originator.
            auto it = sessions_.find({id.da, id.sa});
            if (it == sessions_.end() || it->second.broadcast || it->second.pgn != pgn) return;
            auto& s = it->second;
            s.last_us = frame.t_us;
            const std::size_t count = frame.data[1];
            const std::size_t next = frame.data[2];
            if (count == 0) return;  // "hold the connection open"
            // The receiver may ask for packets again (a retransmission) but never for ones not yet sent.
            if (next < 1 || next > s.next_seq || next > s.packets) {
                ++stats_.sequence_errors;
                sessions_.erase(it);
                return;
            }
            s.next_seq = next;
            s.data.resize(std::min(s.data.size(), (next - 1) * 7));
            return;
        }
        case kCtrlEndOfMsgAck:
            ++stats_.end_of_msg_ack;
            return;
        case kCtrlAbort: {
            ++stats_.aborts_seen;
            // Either side may abort, so close a matching session in either direction.
            for (const Key& key : {Key{id.sa, id.da}, Key{id.da, id.sa}}) {
                auto it = sessions_.find(key);
                if (it != sessions_.end() && !it->second.broadcast && it->second.pgn == pgn) {
                    sessions_.erase(it);
                    ++stats_.aborted_sessions;
                }
            }
            return;
        }
        default:
            ++stats_.malformed_tp_frames;
            return;
    }
}

void Reassembler::on_data(const can::Frame& frame, const Id& id, const Sink& sink) {
    if (frame.dlc != 8) {
        ++stats_.malformed_tp_frames;
        return;
    }
    auto it = sessions_.find({id.sa, id.da});
    if (it == sessions_.end()) {
        ++stats_.orphan_data;
        return;
    }
    auto& s = it->second;
    if (frame.data[0] != s.next_seq) {
        ++stats_.sequence_errors;
        sessions_.erase(it);
        return;
    }
    const std::size_t take = std::min<std::size_t>(7, s.size - s.data.size());
    s.data.insert(s.data.end(), frame.data.begin() + 1, frame.data.begin() + 1 + static_cast<std::ptrdiff_t>(take));
    s.last_us = frame.t_us;
    ++s.next_seq;
    if (s.next_seq <= s.packets) return;

    Message m;
    m.t_us = frame.t_us;
    m.priority = s.priority;
    m.pgn = s.pgn;
    m.sa = id.sa;
    m.da = id.da;
    m.data = std::move(s.data);
    m.multipacket = true;
    if (s.broadcast) {
        ++stats_.completed_bam;
    } else {
        ++stats_.completed_cmdt;
    }
    sessions_.erase(it);
    sink(m);
}

}  // namespace vnsl::j1939
