#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "vnsl/j1939/transport.hpp"
#include "vnsl/sim/simulator.hpp"

namespace vnsl::sim {

/// Counters for one node's J1939 stack.
struct NodeStats {
    std::uint64_t frames_sent = 0;
    std::uint64_t claims_sent = 0;
    std::uint64_t claims_lost = 0;     ///< times another node's claim beat ours
    std::uint64_t claims_defended = 0; ///< times we re-claimed against a weaker claim
    std::uint64_t requests_answered = 0;
    std::uint64_t nacks_sent = 0;
    std::uint64_t bam_sent = 0;
    std::uint64_t cmdt_sent = 0;       ///< connection-mode transfers completed (EndOfMsgAck received)
    std::uint64_t cmdt_received = 0;   ///< connection-mode transfers to us, acknowledged
    std::uint64_t cmdt_failed = 0;     ///< our transfers aborted or timed out
};

/// A J1939 node that takes part in the network, the counterpart of the passive Reassembler.
///
/// - Address claim (J1939-81): claims its preferred address at start and waits 250 ms before
///   sending anything else. If another node claims the same address with a lower NAME (higher
///   priority), it moves to a free address in 128..247 if it is arbitrary-address capable, or
///   sends Cannot Claim and goes silent. It defends its address against weaker claims and
///   answers requests for Address Claimed.
/// - Requests (PGN 59904): asks the subclass for the payload; a request sent to this node for a
///   group it does not have gets a negative acknowledgement.
/// - Transport (J1939-21) as sender: payloads over 8 bytes go by BAM (50 ms between packets)
///   when addressed to everyone, or by RTS/CTS when addressed to one node. As receiver: answers
///   an RTS with CTS (up to 16 packets at a time) and acknowledges with EndOfMsgAck.
class J1939Node : public Node {
public:
    J1939Node(std::string label, std::uint64_t name, std::uint8_t preferred_address, bool arbitrary_capable);

    enum class ClaimState : std::uint8_t { Idle, Claiming, Claimed, CannotClaim };

    /// Delays power-up (the first address claim) by `delay_us`; use before the run starts.
    void set_start_delay(std::uint64_t delay_us) { start_delay_us_ = delay_us; }

    [[nodiscard]] std::uint8_t address() const { return address_; }
    [[nodiscard]] ClaimState claim_state() const { return state_; }
    [[nodiscard]] std::uint64_t name() const { return name_; }
    [[nodiscard]] const std::string& label() const { return label_; }
    [[nodiscard]] const NodeStats& node_stats() const { return stats_; }

    void start(Simulator& sim) final;
    void on_frame(Simulator& sim, const can::Frame& frame) final;
    void on_timer(Simulator& sim, int timer_id) final;

    static constexpr std::uint64_t kClaimWaitUs = 250'000;
    static constexpr std::uint64_t kBamGapUs = 50'000;
    static constexpr std::uint64_t kT3Us = 1'250'000;  ///< sender's wait for CTS or EndOfMsgAck
    static constexpr std::size_t kMaxPacketsPerCts = 16;

protected:
    /// Sends a message: one frame if it fits, otherwise BAM (to everyone) or RTS/CTS (to one
    /// node). Ignored until the address is claimed.
    void send(Simulator& sim, std::uint8_t priority, std::uint32_t pgn, std::uint8_t da,
              std::span<const std::uint8_t> data);

    /// Schedules an application timer (`id` >= 0) at an absolute time.
    void schedule_app(Simulator& sim, std::uint64_t at_us, int id);

    /// Called once the address claim succeeds: start periodic traffic here.
    virtual void on_claimed(Simulator& /*sim*/) {}
    /// Every complete message addressed to this node or to everyone (not requests, claims or
    /// transport frames, which the stack handles).
    virtual void on_message(Simulator& /*sim*/, const j1939::Message& /*m*/) {}
    /// Payload for a requested group, or nullopt if this node does not provide it.
    virtual std::optional<std::vector<std::uint8_t>> on_request(Simulator& /*sim*/, std::uint32_t /*pgn*/,
                                                                std::uint8_t /*requester*/) {
        return std::nullopt;
    }
    virtual void on_app_timer(Simulator& /*sim*/, int /*id*/) {}

private:
    struct Outgoing {
        std::uint8_t priority = 6;
        std::uint32_t pgn = 0;
        std::uint8_t da = 0xFF;
        std::vector<std::uint8_t> data;
    };
    struct Sending {
        Outgoing msg;
        std::size_t packets = 0;
        std::size_t next = 1;          ///< next packet number to send
        std::size_t granted_until = 0; ///< last packet the receiver allowed (RTS/CTS)
        int timer = 0;
    };

    void transmit_frame(Simulator& sim, std::uint8_t priority, std::uint32_t pgn, std::uint8_t sa, std::uint8_t da,
                        std::span<const std::uint8_t> data);
    void send_claim(Simulator& sim);
    void send_cannot_claim(Simulator& sim);
    void handle_claim(Simulator& sim, std::uint8_t sa, std::uint64_t other);
    void handle_request(Simulator& sim, const j1939::Message& m);
    void handle_tp_cm(Simulator& sim, const can::Frame& frame, std::uint8_t sa, std::uint8_t da);
    void start_next_bam(Simulator& sim);
    void bam_step(Simulator& sim);
    void cmdt_timeout(Simulator& sim);
    void start_next_cmdt(Simulator& sim);
    void send_dt(Simulator& sim, const Outgoing& msg, std::size_t seq, std::uint8_t da);
    void send_cm(Simulator& sim, std::uint8_t da, std::array<std::uint8_t, 8> bytes);
    int timer_after(Simulator& sim, std::uint64_t delay_us, std::function<void()> action);
    void cancel(int timer_id);
    [[nodiscard]] std::uint8_t pick_free_address() const;

    std::string label_;
    std::uint64_t name_;
    std::uint8_t preferred_;
    bool arbitrary_capable_;
    std::uint64_t start_delay_us_ = 0;
    std::uint8_t address_ = j1939::kNullAddress;
    ClaimState state_ = ClaimState::Idle;
    std::map<std::uint8_t, std::uint64_t> seen_claims_;  ///< other nodes' addresses and NAMEs
    j1939::Reassembler reassembler_;
    std::deque<Outgoing> bam_queue_;
    std::optional<Sending> bam_;
    std::deque<Outgoing> cmdt_queue_;
    std::optional<Sending> cmdt_;
    struct Receiving {
        std::uint8_t peer = 0;
        std::uint32_t pgn = 0;
        std::size_t packets = 0;
        std::size_t batch_end = 0;  ///< last packet granted by our latest CTS
    };
    std::vector<Receiving> cmdt_receive_;
    std::map<int, std::function<void()>> internal_timers_;
    int next_internal_ = -1;
    NodeStats stats_;
};

}  // namespace vnsl::sim
