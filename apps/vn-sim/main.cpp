// vn-sim: runs the simulated truck on a simulated 250 kbit/s bus and writes every frame as a
// candump -l log.
//
//   vn-sim [--duration SECONDS] [--seed N] [--conflict] [--iface-name NAME] [--summary] [--out FILE]
//
// Same seed, same log: the simulation never reads the wall clock.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <format>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "vnsl/can/frame.hpp"
#ifdef __linux__
#include <ctime>

#include "vnsl/can/socketcan.hpp"
#endif
#include "vnsl/sim/simulator.hpp"
#include "vnsl/sim/truck.hpp"

namespace {

void usage() {
    std::cerr << "usage: vn-sim [--duration SECONDS] [--seed N] [--conflict] [--iface-name NAME] [--summary] [--out FILE]\n"
                 "              [--iface IFACE]   run in real time on a SocketCAN interface (Linux)\n";
}

#ifdef __linux__
std::uint64_t mono_us() {
    timespec ts{};
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000ULL + static_cast<std::uint64_t>(ts.tv_nsec) / 1000;
}

/// Runs the simulation against the wall clock on a real interface: every frame the simulated
/// nodes complete is sent to the interface at its simulated time, and every frame arriving from
/// the interface is injected into the simulated bus, where the ECUs see it like any other.
void run_live(vnsl::sim::Simulator& sim, const std::string& ifname, std::uint64_t end_us) {
    vnsl::can::SocketCan sock(ifname);
    sim.on_wire([&](const vnsl::can::Frame& f, std::size_t sender) {
        if (sender != vnsl::sim::Simulator::kExternal) sock.send(f);  // injected frames came from the interface
    });
    sim.run_until(0);  // start the nodes
    const std::uint64_t wall0 = mono_us();
    while (sim.now() < end_us) {
        const std::uint64_t next = std::min(sim.next_event_time(), end_us);
        const std::uint64_t now = mono_us() - wall0;
        if (now < next) {
            const int timeout_ms = static_cast<int>(std::min<std::uint64_t>((next - now + 999) / 1000, 1000));
            if (auto rx = sock.receive(timeout_ms)) {
                sim.run_until(std::min(mono_us() - wall0, end_us));
                sim.inject(*rx);
                continue;
            }
            if (mono_us() - wall0 < next) continue;
        }
        sim.run_until(next);
    }
}
#endif

int run(int argc, char** argv) {
    double duration_s = 60;
    vnsl::sim::TruckConfig cfg;
    std::string iface = "vcan0";
    std::string out_path;
    std::string live_iface;
    bool summary = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        const auto next = [&]() -> std::string {
            if (i + 1 >= argc) throw std::invalid_argument("missing value after " + std::string(a));
            return argv[++i];
        };
        if (a == "--duration") {
            duration_s = std::stod(next());
        } else if (a == "--seed") {
            cfg.seed = std::stoull(next());
        } else if (a == "--conflict") {
            cfg.address_conflict = true;
        } else if (a == "--iface-name") {
            iface = next();
        } else if (a == "--out") {
            out_path = next();
        } else if (a == "--summary") {
            summary = true;
        } else if (a == "--iface") {
            live_iface = next();
            iface = live_iface;
        } else {
            usage();
            return a == "-h" || a == "--help" ? 0 : 2;
        }
    }
    if (!(duration_s > 0) || duration_s > 7 * 24 * 3600) {
        std::cerr << "vn-sim: duration must be between 0 and one week\n";
        return 2;
    }

    std::ofstream file;
    if (!out_path.empty()) {
        file.open(out_path);
        if (!file) {
            std::cerr << "vn-sim: cannot write " << out_path << '\n';
            return 1;
        }
    }
    std::ostream& out = out_path.empty() ? std::cout : file;
    std::ios::sync_with_stdio(false);

    vnsl::sim::Simulator sim(250'000);
    const vnsl::sim::Truck truck(sim, cfg);
    const std::uint64_t epoch_us = cfg.start_epoch_s * 1'000'000ULL;
    sim.on_wire([&](const vnsl::can::Frame& f, std::size_t) {
        auto stamped = f;
        stamped.t_us += epoch_us;
        out << vnsl::can::format_candump(stamped, iface) << '\n';
    });
    const auto end_us = static_cast<std::uint64_t>(duration_s * 1e6);
    if (live_iface.empty()) {
        sim.run_until(end_us);
    } else {
#ifdef __linux__
        run_live(sim, live_iface, end_us);
#else
        std::cerr << "vn-sim: --iface needs Linux SocketCAN\n";
        return 2;
#endif
    }
    out.flush();

    if (summary) {
        const auto& st = sim.stats();
        const double load = 100.0 * static_cast<double>(st.busy_us) / (duration_s * 1e6);
        std::cerr << std::format("simulated {:.1f} s at 250 kbit/s: {} frames, bus load {:.1f} %\n", duration_s,
                                 st.frames, load);
        std::cerr << std::format(
            "arbitration: {} contested starts, {} frames waited; longest wait {} us; most queued {}\n",
            st.arbitrations, st.lost_arbitration, st.max_wait_us, st.max_queue);
        std::cerr << std::format("{:<15} {:>4} {:>8} {:>6} {:>5} {:>5} {:>6} {:>5}\n", "node", "addr", "frames",
                                 "claims", "BAM", "RTS", "rxRTS", "NACK");
        for (const auto* n : truck.nodes()) {
            const auto& s = n->node_stats();
            std::cerr << std::format("{:<15} 0x{:02X} {:>8} {:>6} {:>5} {:>5} {:>6} {:>5}\n", n->label(),
                                     n->address(), s.frames_sent, s.claims_sent, s.bam_sent, s.cmdt_sent,
                                     s.cmdt_received, s.nacks_sent);
        }
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        (void)std::fputs("vn-sim: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("vn-sim: unexpected error\n", stderr);
    }
    return 1;
}
