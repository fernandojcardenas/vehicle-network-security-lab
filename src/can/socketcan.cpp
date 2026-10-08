#include "vnsl/can/socketcan.hpp"

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace vnsl::can {
namespace {

[[noreturn]] void fail(const char* what) { throw std::system_error(errno, std::generic_category(), what); }

}  // namespace

SocketCan::SocketCan(const std::string& ifname) : name_(ifname) {
    if (ifname.empty() || ifname.size() >= IFNAMSIZ) throw std::invalid_argument("bad CAN interface name");
    fd_ = ::socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd_ < 0) fail("socket(PF_CAN)");
    try {
        ifreq ifr{};
        std::copy(ifname.begin(), ifname.end(), ifr.ifr_name);
        if (::ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) fail("ioctl(SIOCGIFINDEX)");
        const int on = 1;
        if (::setsockopt(fd_, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof on) < 0) fail("setsockopt(SO_TIMESTAMP)");
        sockaddr_can addr{};
        addr.can_family = AF_CAN;
        addr.can_ifindex = ifr.ifr_ifindex;
        if (::bind(fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) < 0) fail("bind");
    } catch (...) {
        ::close(fd_);
        fd_ = -1;
        throw;
    }
}

SocketCan::~SocketCan() {
    if (fd_ >= 0) ::close(fd_);
}

SocketCan::SocketCan(SocketCan&& other) noexcept : fd_(std::exchange(other.fd_, -1)), name_(std::move(other.name_)) {}

SocketCan& SocketCan::operator=(SocketCan&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = std::exchange(other.fd_, -1);
        name_ = std::move(other.name_);
    }
    return *this;
}

void SocketCan::send(const Frame& frame) {
    can_frame cf{};
    cf.can_id = frame.extended ? ((frame.id & CAN_EFF_MASK) | CAN_EFF_FLAG) : (frame.id & CAN_SFF_MASK);
    cf.len = std::min<std::uint8_t>(frame.dlc, 8);
    std::copy_n(frame.data.begin(), cf.len, cf.data);
    while (true) {
        const ssize_t n = ::write(fd_, &cf, sizeof cf);
        if (n == static_cast<ssize_t>(sizeof cf)) return;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == ENOBUFS) {  // interface queue full: wait until writable
            pollfd p{fd_, POLLOUT, 0};
            (void)::poll(&p, 1, 100);
            continue;
        }
        fail("write(CAN)");
    }
}

std::optional<Frame> SocketCan::receive(int timeout_ms) {
    while (true) {
        pollfd p{fd_, POLLIN, 0};
        const int r = ::poll(&p, 1, timeout_ms);
        if (r == 0) return std::nullopt;
        if (r < 0) {
            if (errno == EINTR) return std::nullopt;
            fail("poll(CAN)");
        }
        can_frame cf{};
        iovec iov{&cf, sizeof cf};
        alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(timeval))> control{};
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.data();
        msg.msg_controllen = control.size();
        const ssize_t n = ::recvmsg(fd_, &msg, 0);
        if (n < 0) {
            if (errno == EINTR) return std::nullopt;
            fail("recvmsg(CAN)");
        }
        if (n != static_cast<ssize_t>(sizeof cf)) continue;  // CAN FD frame: not used here
        if ((cf.can_id & (CAN_RTR_FLAG | CAN_ERR_FLAG)) != 0) continue;
        Frame f;
        f.extended = (cf.can_id & CAN_EFF_FLAG) != 0;
        f.id = f.extended ? (cf.can_id & CAN_EFF_MASK) : (cf.can_id & CAN_SFF_MASK);
        f.dlc = std::min<std::uint8_t>(cf.len, 8);
        std::copy_n(cf.data, f.dlc, f.data.begin());
        for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_TIMESTAMP) {
                timeval tv{};
                std::memcpy(&tv, CMSG_DATA(c), sizeof tv);
                f.t_us = static_cast<std::uint64_t>(tv.tv_sec) * 1'000'000ULL + static_cast<std::uint64_t>(tv.tv_usec);
            }
        }
        if (f.t_us == 0) {
            timeval tv{};
            ::gettimeofday(&tv, nullptr);
            f.t_us = static_cast<std::uint64_t>(tv.tv_sec) * 1'000'000ULL + static_cast<std::uint64_t>(tv.tv_usec);
        }
        return f;
    }
}

}  // namespace vnsl::can
