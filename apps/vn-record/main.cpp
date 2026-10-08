// vn-record: records every frame on a SocketCAN interface as a candump -l log, with the
// kernel's receive timestamps.
//
//   vn-record IFACE [--duration SECONDS] [--count N]
//
// Stops after the duration, after N frames, or on SIGINT/SIGTERM, and always flushes.

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iostream>
#include <string>
#include <string_view>
#include <sys/time.h>

#include "vnsl/can/frame.hpp"
#include "vnsl/can/socketcan.hpp"

namespace {

volatile std::sig_atomic_t g_stop = 0;
extern "C" void on_signal(int /*sig*/) { g_stop = 1; }

std::uint64_t wall_us() {
    timeval tv{};
    ::gettimeofday(&tv, nullptr);
    return static_cast<std::uint64_t>(tv.tv_sec) * 1'000'000ULL + static_cast<std::uint64_t>(tv.tv_usec);
}

int run(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: vn-record IFACE [--duration SECONDS] [--count N]\n";
        return 2;
    }
    const std::string iface = argv[1];
    double duration_s = 0;
    std::uint64_t count = 0;
    for (int i = 2; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--duration" && i + 1 < argc) {
            duration_s = std::stod(argv[++i]);
        } else if (a == "--count" && i + 1 < argc) {
            count = std::stoull(argv[++i]);
        } else {
            std::cerr << "vn-record: unknown argument " << a << '\n';
            return 2;
        }
    }
    struct sigaction sa {};
    sa.sa_handler = on_signal;  // no SA_RESTART: poll returns EINTR and the loop ends
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    vnsl::can::SocketCan sock(iface);
    std::ios::sync_with_stdio(false);
    const std::uint64_t start = wall_us();
    const std::uint64_t end = duration_s > 0 ? start + static_cast<std::uint64_t>(duration_s * 1e6) : 0;
    std::uint64_t n = 0;
    while (g_stop == 0) {
        int timeout = 200;
        if (end != 0) {
            const std::uint64_t now = wall_us();
            if (now >= end) break;
            timeout = static_cast<int>(std::min<std::uint64_t>(200, (end - now) / 1000 + 1));
        }
        const auto f = sock.receive(timeout);
        if (!f) continue;
        std::cout << vnsl::can::format_candump(*f, iface) << '\n';
        if (count != 0 && ++n >= count) break;
    }
    std::cout.flush();
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        (void)std::fputs("vn-record: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("vn-record: unexpected error\n", stderr);
    }
    return 1;
}
