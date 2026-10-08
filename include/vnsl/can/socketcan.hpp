#pragma once

// Linux SocketCAN raw socket. Only built on Linux (the rest of the library is portable).

#include <cstdint>
#include <optional>
#include <string>

#include "vnsl/can/frame.hpp"

namespace vnsl::can {

/// A raw CAN socket bound to one interface (`can0`, `vcan0`, ...).
///
/// Received frames carry the kernel's receive timestamp. Frames this socket sends are not
/// received back (CAN_RAW_RECV_OWN_MSGS stays off, the kernel default). Errors throw
/// std::system_error with the failing call in the message.
class SocketCan {
public:
    explicit SocketCan(const std::string& ifname);
    ~SocketCan();
    SocketCan(const SocketCan&) = delete;
    SocketCan& operator=(const SocketCan&) = delete;
    SocketCan(SocketCan&& other) noexcept;
    SocketCan& operator=(SocketCan&& other) noexcept;

    /// Sends one classic data frame. Blocks if the interface queue is full.
    void send(const Frame& frame);

    /// Waits up to `timeout_ms` (negative: forever) for a frame. Returns nullopt on timeout or
    /// if interrupted by a signal. Remote, error and CAN FD frames are skipped.
    std::optional<Frame> receive(int timeout_ms);

    [[nodiscard]] int fd() const { return fd_; }
    [[nodiscard]] const std::string& name() const { return name_; }

private:
    int fd_ = -1;
    std::string name_;
};

}  // namespace vnsl::can
