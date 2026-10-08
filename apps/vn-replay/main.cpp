// vn-replay: sends a candump -l log to a SocketCAN interface with its original timing,
// optionally sped up.
//
//   vn-replay LOG IFACE [--speed FACTOR]
//
// Timing follows the log's own timestamps relative to its first frame, scheduled against
// absolute deadlines so error does not accumulate. Prints how far behind schedule the
// replay ever ran.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <exception>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "vnsl/can/frame.hpp"
#include "vnsl/can/socketcan.hpp"

namespace {

std::uint64_t mono_us() {
    timespec ts{};
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000ULL + static_cast<std::uint64_t>(ts.tv_nsec) / 1000;
}

void sleep_until_us(std::uint64_t deadline) {
    timespec ts{};
    ts.tv_sec = static_cast<time_t>(deadline / 1'000'000ULL);
    ts.tv_nsec = static_cast<long>((deadline % 1'000'000ULL) * 1000);
    while (::clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, nullptr) != 0) {
    }
}

int run(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: vn-replay LOG IFACE [--speed FACTOR]\n";
        return 2;
    }
    const std::string path = argv[1];
    const std::string iface = argv[2];
    double speed = 1.0;
    for (int i = 3; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--speed" && i + 1 < argc) {
            speed = std::stod(argv[++i]);
        } else {
            std::cerr << "vn-replay: unknown argument " << a << '\n';
            return 2;
        }
    }
    if (!(speed > 0)) {
        std::cerr << "vn-replay: speed must be positive\n";
        return 2;
    }
    std::ifstream in(path);
    if (!in) {
        std::cerr << "vn-replay: cannot open " << path << '\n';
        return 1;
    }
    std::vector<vnsl::can::Frame> frames;
    std::size_t bad = 0;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (auto f = vnsl::can::parse_candump_line(line)) {
            frames.push_back(*f);
        } else {
            ++bad;
        }
    }
    if (frames.empty()) {
        std::cerr << "vn-replay: no frames in " << path << '\n';
        return 1;
    }

    vnsl::can::SocketCan sock(iface);
    const std::uint64_t log_start = frames.front().t_us;
    const std::uint64_t wall_start = mono_us() + 10'000;
    std::uint64_t worst_late_us = 0;
    for (const auto& f : frames) {
        const auto offset = static_cast<std::uint64_t>(static_cast<double>(f.t_us - std::min(f.t_us, log_start)) / speed);
        const std::uint64_t deadline = wall_start + offset;
        const std::uint64_t now = mono_us();
        if (now < deadline) {
            sleep_until_us(deadline);
        } else {
            worst_late_us = std::max(worst_late_us, now - deadline);
        }
        sock.send(f);
    }
    std::cerr << "vn-replay: sent " << frames.size() << " frames (" << bad << " unparsed lines), speed " << speed
              << "x, worst lateness " << worst_late_us << " us\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        (void)std::fputs("vn-replay: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("vn-replay: unexpected error\n", stderr);
    }
    return 1;
}
