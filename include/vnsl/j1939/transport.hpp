#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <utility>
#include <vector>

#include "vnsl/can/frame.hpp"
#include "vnsl/j1939/id.hpp"

namespace vnsl::j1939 {

/// A complete J1939 message: either a single frame or a reassembled multi-packet transfer.
struct Message {
    std::uint64_t t_us = 0;  ///< time of the frame that completed it
    std::uint8_t priority = 0;
    std::uint32_t pgn = 0;
    std::uint8_t sa = 0;
    std::uint8_t da = kGlobalAddress;
    std::vector<std::uint8_t> data;
    bool multipacket = false;  ///< true if it arrived through the transport protocol
};

/// Counters for everything the transport layer saw, including every way a transfer can fail.
/// An intrusion detector reads these: a healthy bus has almost no failures.
struct TransportStats {
    std::uint64_t frames = 0;                ///< every frame offered
    std::uint64_t ignored_non_j1939 = 0;     ///< 11-bit frames
    std::uint64_t single_frame_messages = 0;
    std::uint64_t bam_started = 0;
    std::uint64_t rts_started = 0;
    std::uint64_t completed_bam = 0;
    std::uint64_t completed_cmdt = 0;
    std::uint64_t cts = 0;
    std::uint64_t end_of_msg_ack = 0;
    std::uint64_t aborts_seen = 0;           ///< TP.CM Connection Abort frames on the bus
    std::uint64_t aborted_sessions = 0;      ///< open sessions those aborts closed
    std::uint64_t timeouts = 0;              ///< sessions that went quiet too long
    std::uint64_t sequence_errors = 0;       ///< TP.DT out of order (session dropped)
    std::uint64_t bad_announcements = 0;     ///< RTS/BAM with impossible size/count or a TP PGN inside
    std::uint64_t replaced_sessions = 0;     ///< new RTS/BAM while one was open for the same pair
    std::uint64_t rejected_too_many_sessions = 0;
    std::uint64_t orphan_data = 0;           ///< TP.DT with no open session
    std::uint64_t malformed_tp_frames = 0;   ///< TP.CM/TP.DT shorter than 8 bytes, unknown control byte
};

/// Passive J1939-21 transport-protocol reassembler.
///
/// It listens to a bus (or a log) rather than taking part, the way a logger or an intrusion
/// detector does: it follows both broadcast transfers (BAM) and connection-mode transfers
/// (RTS/CTS) between any pair of nodes, without ever replying. Every non-transport frame is
/// passed through as a single-frame Message; TP.CM and TP.DT frames are consumed and their
/// reassembled payload is emitted once complete.
///
/// Untrusted input: every size and count an announcement claims is checked before use, the
/// payload buffer never exceeds 1785 bytes, and the number of open sessions is bounded.
class Reassembler {
public:
    struct Limits {
        std::size_t max_sessions = 64;           ///< open transfers at once (J1939 allows at most a few)
        std::uint64_t bam_packet_timeout_us = 750'000;   ///< T1: longest gap between BAM packets
        std::uint64_t cmdt_timeout_us = 1'250'000;       ///< T2/T3: longest silence in a connection
    };

    using Sink = std::function<void(const Message&)>;

    Reassembler() : Reassembler(Limits{}) {}
    explicit Reassembler(Limits limits) : limits_(limits) {}

    /// Offers one frame. Expires stale sessions first (using the frame's time), then emits any
    /// message the frame completes. Times must not go backwards by more than the timeouts.
    void on_frame(const can::Frame& frame, const Sink& sink);

    /// Drops every session that has been silent past its timeout at time `now_us`.
    void expire(std::uint64_t now_us);

    [[nodiscard]] const TransportStats& stats() const { return stats_; }
    [[nodiscard]] std::size_t open_sessions() const { return sessions_.size(); }

    static constexpr std::size_t kMaxPayload = 1785;  ///< 255 packets x 7 bytes
    static constexpr std::size_t kMaxPackets = 255;

private:
    struct Session {
        bool broadcast = false;
        std::uint8_t priority = 0;
        std::uint32_t pgn = 0;
        std::size_t size = 0;
        std::size_t packets = 0;
        std::size_t next_seq = 1;
        std::uint64_t last_us = 0;
        std::vector<std::uint8_t> data;
    };
    using Key = std::pair<std::uint8_t, std::uint8_t>;  ///< (originator SA, destination DA)

    void on_connection(const can::Frame& frame, const Id& id);
    void on_data(const can::Frame& frame, const Id& id, const Sink& sink);
    void start_session(const Key& key, Session session);

    Limits limits_;
    TransportStats stats_;
    std::map<Key, Session> sessions_;
};

}  // namespace vnsl::j1939
