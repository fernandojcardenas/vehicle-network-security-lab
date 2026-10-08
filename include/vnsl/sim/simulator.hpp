#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <queue>
#include <vector>

#include "vnsl/can/frame.hpp"

namespace vnsl::sim {

class Simulator;

/// Something attached to the simulated bus: an ECU, a tool, a logger.
class Node {
public:
    Node() = default;
    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;
    Node(Node&&) = delete;
    Node& operator=(Node&&) = delete;
    virtual ~Node() = default;

    /// Called once when the simulation starts.
    virtual void start(Simulator& /*sim*/) {}
    /// Called for every frame another node (or an external source) completed on the bus.
    virtual void on_frame(Simulator& /*sim*/, const can::Frame& /*frame*/) {}
    /// Called when a timer this node scheduled fires.
    virtual void on_timer(Simulator& /*sim*/, int /*timer_id*/) {}

    [[nodiscard]] std::size_t index() const { return index_; }

private:
    friend class Simulator;
    std::size_t index_ = 0;
};

/// Bus counters.
struct BusStats {
    std::uint64_t frames = 0;
    std::uint64_t bits = 0;          ///< on-wire bits including stuffing and intermission
    std::uint64_t busy_us = 0;       ///< time the bus carried a frame
    std::uint64_t arbitrations = 0;  ///< times two or more nodes wanted the bus at once
    std::uint64_t lost_arbitration = 0;  ///< frames that had to wait because a lower ID won
    std::uint64_t max_wait_us = 0;   ///< longest a frame waited between queueing and starting
    std::size_t max_queue = 0;       ///< most frames waiting at once, all nodes together
};

/// A discrete-event simulation of one classic CAN bus.
///
/// Time is simulated (microseconds from 0) and nothing depends on the wall clock, so a run is
/// exactly reproducible. The bus model follows CAN: one frame at a time; when several nodes
/// have a frame ready, the lowest identifier wins arbitration and the others wait; each node
/// transmits its own frames in order; a frame occupies the bus for its real bit count
/// (bit stuffing and intermission included) at the configured bit rate. A frame is delivered
/// to every other node, stamped with the time its last bit left the wire.
class Simulator {
public:
    explicit Simulator(std::uint32_t bitrate = 250'000) : bitrate_(bitrate) {}

    /// Attaches a node. Nodes must outlive the simulator's run.
    void add(Node& node);

    /// Starts every node (once) and processes events until `t_us` (inclusive).
    void run_until(std::uint64_t t_us);

    /// Time of the next pending event, or max() if none.
    [[nodiscard]] std::uint64_t next_event_time() const;

    [[nodiscard]] std::uint64_t now() const { return now_; }
    [[nodiscard]] std::uint32_t bitrate() const { return bitrate_; }

    /// Fires `node.on_timer(timer_id)` at `at_us` (not earlier than now).
    void schedule(Node& node, std::uint64_t at_us, int timer_id);

    /// Queues a frame from `node` for the bus.
    void transmit(Node& node, const can::Frame& frame);

    /// Queues a frame from outside the simulation (a real interface, an attacker). It arbitrates
    /// like any node and is delivered to every node.
    void inject(const can::Frame& frame);

    /// Called for every frame completed on the bus, with the index of its sender (kExternal
    /// for injected frames). Use it for logging or to forward frames to a real interface.
    using WireObserver = std::function<void(const can::Frame&, std::size_t sender)>;
    void on_wire(WireObserver observer) { observers_.push_back(std::move(observer)); }

    [[nodiscard]] const BusStats& stats() const { return stats_; }

    static constexpr std::size_t kExternal = std::numeric_limits<std::size_t>::max();

private:
    struct Event {
        std::uint64_t t = 0;
        std::uint64_t seq = 0;  ///< tie-break: events at the same time run in the order scheduled
        enum class Kind : std::uint8_t { Timer, BusDone, Arbitrate } kind = Kind::Timer;
        std::size_t node = 0;
        int timer = 0;
        bool operator>(const Event& o) const { return t != o.t ? t > o.t : seq > o.seq; }
    };
    struct Pending {
        can::Frame frame;
        std::uint64_t queued_at = 0;
    };

    void push_event(Event e);
    void request_arbitration();
    void arbitrate();
    void finish_transmission();
    std::deque<Pending>& queue_for(std::size_t sender);
    [[nodiscard]] std::size_t total_queued() const;

    std::uint32_t bitrate_;
    std::uint64_t now_ = 0;
    std::uint64_t seq_ = 0;
    bool started_ = false;
    std::vector<Node*> nodes_;
    std::vector<std::deque<Pending>> queues_;  ///< one per node
    std::deque<Pending> external_;             ///< injected frames
    bool arbitration_pending_ = false;         ///< an Arbitrate event is queued for the current time
    std::priority_queue<Event, std::vector<Event>, std::greater<>> events_;
    bool bus_busy_ = false;
    std::size_t on_wire_sender_ = 0;
    can::Frame on_wire_frame_;
    std::vector<WireObserver> observers_;
    BusStats stats_;
};

}  // namespace vnsl::sim
