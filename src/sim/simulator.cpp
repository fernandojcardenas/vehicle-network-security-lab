#include "vnsl/sim/simulator.hpp"

#include <algorithm>

#include "vnsl/can/bit_timing.hpp"

namespace vnsl::sim {

void Simulator::add(Node& node) {
    node.index_ = nodes_.size();
    nodes_.push_back(&node);
    queues_.resize(nodes_.size());
}

std::deque<Simulator::Pending>& Simulator::queue_for(std::size_t sender) {
    return sender == kExternal ? external_ : queues_.at(sender);
}

std::size_t Simulator::total_queued() const {
    std::size_t n = external_.size();
    for (const auto& q : queues_) n += q.size();
    return n;
}

void Simulator::push_event(Event e) {
    e.seq = seq_++;
    events_.push(e);
}

void Simulator::schedule(Node& node, std::uint64_t at_us, int timer_id) {
    Event e;
    e.t = std::max(at_us, now_);
    e.node = node.index();
    e.timer = timer_id;
    push_event(e);
}

void Simulator::transmit(Node& node, const can::Frame& frame) {
    queue_for(node.index()).push_back({frame, now_});
    stats_.max_queue = std::max(stats_.max_queue, total_queued());
    request_arbitration();
}

void Simulator::inject(const can::Frame& frame) {
    queue_for(kExternal).push_back({frame, now_});
    stats_.max_queue = std::max(stats_.max_queue, total_queued());
    request_arbitration();
}

// Frames that become ready at the same instant must arbitrate together, so instead of starting
// at once, arbitration runs as its own event after every other event already queued for now.
void Simulator::request_arbitration() {
    if (bus_busy_ || arbitration_pending_) return;
    arbitration_pending_ = true;
    Event e;
    e.t = now_;
    e.kind = Event::Kind::Arbitrate;
    push_event(e);
}

void Simulator::arbitrate() {
    arbitration_pending_ = false;
    if (bus_busy_) return;
    // Arbitration: among the frame at the head of every node's queue (and the external queue),
    // the lowest identifier wins. J1939 uses only 29-bit frames, which compare by value.
    std::deque<Pending>* winner = nullptr;
    std::size_t winner_sender = 0;
    std::size_t contenders = 0;
    const auto consider = [&](std::deque<Pending>& q, std::size_t sender) {
        if (q.empty()) return;
        ++contenders;
        if (winner == nullptr || q.front().frame.id < winner->front().frame.id) {
            winner = &q;
            winner_sender = sender;
        }
    };
    for (std::size_t i = 0; i < queues_.size(); ++i) consider(queues_[i], i);
    consider(external_, kExternal);
    if (winner == nullptr) return;
    if (contenders > 1) {
        ++stats_.arbitrations;
        stats_.lost_arbitration += contenders - 1;
    }
    const Pending p = winner->front();
    winner->pop_front();
    stats_.max_wait_us = std::max(stats_.max_wait_us, now_ - p.queued_at);

    const auto bits = can::frame_bits(p.frame).total();
    const std::uint64_t duration = (bits * 1'000'000ULL + bitrate_ - 1) / bitrate_;
    bus_busy_ = true;
    on_wire_frame_ = p.frame;
    on_wire_sender_ = winner_sender;
    stats_.bits += bits;
    stats_.busy_us += duration;
    Event e;
    e.t = now_ + duration;
    e.kind = Event::Kind::BusDone;
    push_event(e);
}

void Simulator::finish_transmission() {
    bus_busy_ = false;
    can::Frame f = on_wire_frame_;
    f.t_us = now_;
    const std::size_t sender = on_wire_sender_;
    ++stats_.frames;
    for (const auto& obs : observers_) obs(f, sender);
    for (Node* n : nodes_)
        if (n->index() != sender) n->on_frame(*this, f);
    request_arbitration();
}

std::uint64_t Simulator::next_event_time() const {
    return events_.empty() ? std::numeric_limits<std::uint64_t>::max() : events_.top().t;
}

void Simulator::run_until(std::uint64_t t_us) {
    if (!started_) {
        started_ = true;
        for (Node* n : nodes_) n->start(*this);
    }
    while (!events_.empty() && events_.top().t <= t_us) {
        const Event e = events_.top();
        events_.pop();
        now_ = e.t;
        switch (e.kind) {
            case Event::Kind::BusDone:
                finish_transmission();
                break;
            case Event::Kind::Arbitrate:
                arbitrate();
                break;
            case Event::Kind::Timer:
                nodes_[e.node]->on_timer(*this, e.timer);
                break;
        }
    }
    now_ = std::max(now_, t_us);
}

}  // namespace vnsl::sim
