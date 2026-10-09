// vn-gateway: a default-deny CAN gateway between two buses, driven by a text policy.
//
//   vn-gateway offline IN.log --policy FILE [--direction A>B|B>A] [--out OUT.log]
//   vn-gateway live --in IFACE --out IFACE --policy FILE [--direction A>B|B>A] [--duration S]
//
// offline: read a log, forward the frames the policy allows (in the given direction), write
//   them, and report how many were forwarded and how many dropped and why. live: read frames
//   from one SocketCAN interface and write the allowed ones to the other (Linux only).

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

#include "vnsl/can/frame.hpp"
#include "vnsl/gateway/gateway.hpp"
#ifdef __linux__
#include "vnsl/can/socketcan.hpp"
#endif

namespace {

vnsl::gateway::Policy load_policy(const std::string& path) {
    const std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open policy " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    std::string err;
    auto p = vnsl::gateway::Policy::parse(ss.str(), &err);
    if (!p) throw std::runtime_error("policy " + err);
    return *p;
}

void report(const vnsl::gateway::Gateway& gw) {
    const auto& s = gw.stats();
    std::cerr << "vn-gateway: seen " << s.seen << ", forwarded " << s.forwarded << ", denied "
              << (s.denied_no_rule + s.denied_rate) << " (no-rule " << s.denied_no_rule << ", rate " << s.denied_rate
              << ")\n";
}

volatile std::sig_atomic_t g_stop = 0;
extern "C" void on_signal(int /*sig*/) { g_stop = 1; }

int do_offline(int argc, char** argv) {
    std::string in_path;
    std::string policy_path;
    std::string out_path;
    auto dir = vnsl::gateway::Direction::AtoB;
    for (int i = 2; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--policy" && i + 1 < argc) policy_path = argv[++i];
        else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
        else if (a == "--direction" && i + 1 < argc) dir = std::string_view(argv[++i]) == "B>A" ? vnsl::gateway::Direction::BtoA : vnsl::gateway::Direction::AtoB;
        else if (!a.empty() && a[0] != '-') in_path = a;
        else { std::cerr << "vn-gateway: unknown argument " << a << '\n'; return 2; }
    }
    if (in_path.empty() || policy_path.empty()) { std::cerr << "usage: vn-gateway offline IN.log --policy FILE [--direction A>B|B>A] [--out OUT.log]\n"; return 2; }
    vnsl::gateway::Gateway gw(load_policy(policy_path));
    std::ifstream in(in_path, std::ios::binary);
    if (!in) { std::cerr << "vn-gateway: cannot open " << in_path << '\n'; return 1; }
    std::ofstream file;
    if (!out_path.empty()) { file.open(out_path); if (!file) { std::cerr << "vn-gateway: cannot write " << out_path << '\n'; return 1; } }
    std::ostream& out = out_path.empty() ? std::cout : file;
    std::ios::sync_with_stdio(false);
    std::string line;
    std::string iface = "can0";
    std::string got;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (auto f = vnsl::can::parse_candump_line(line, &got)) {
            iface = got;
            if (gw.forward(*f, dir)) out << vnsl::can::format_candump(*f, iface) << '\n';
        }
    }
    out.flush();
    report(gw);
    return 0;
}

#ifdef __linux__
int do_live(int argc, char** argv) {
    std::string in_if;
    std::string out_if;
    std::string policy_path;
    auto dir = vnsl::gateway::Direction::AtoB;
    double duration_s = 0;
    for (int i = 2; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--in" && i + 1 < argc) in_if = argv[++i];
        else if (a == "--out" && i + 1 < argc) out_if = argv[++i];
        else if (a == "--policy" && i + 1 < argc) policy_path = argv[++i];
        else if (a == "--direction" && i + 1 < argc) dir = std::string_view(argv[++i]) == "B>A" ? vnsl::gateway::Direction::BtoA : vnsl::gateway::Direction::AtoB;
        else if (a == "--duration" && i + 1 < argc) duration_s = std::stod(argv[++i]);
        else { std::cerr << "vn-gateway: unknown argument " << a << '\n'; return 2; }
    }
    if (in_if.empty() || out_if.empty() || policy_path.empty()) { std::cerr << "usage: vn-gateway live --in IFACE --out IFACE --policy FILE [--direction A>B|B>A] [--duration S]\n"; return 2; }
    vnsl::gateway::Gateway gw(load_policy(policy_path));
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    vnsl::can::SocketCan in_sock(in_if);
    vnsl::can::SocketCan out_sock(out_if);
    timespec t0{};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (g_stop == 0) {
        if (duration_s > 0) {
            timespec now{};
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (static_cast<double>(now.tv_sec - t0.tv_sec) + static_cast<double>(now.tv_nsec - t0.tv_nsec) / 1e9 >= duration_s) break;
        }
        auto f = in_sock.receive(200);
        if (!f) continue;
        if (gw.forward(*f, dir)) out_sock.send(*f);
    }
    report(gw);
    return 0;
}
#endif

int run(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: vn-gateway offline|live ...\n"; return 2; }
    const std::string_view mode = argv[1];
    if (mode == "offline") return do_offline(argc, argv);
    if (mode == "live") {
#ifdef __linux__
        return do_live(argc, argv);
#else
        std::cerr << "vn-gateway: live mode needs Linux SocketCAN\n";
        return 2;
#endif
    }
    std::cerr << "vn-gateway: mode must be offline or live\n";
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        (void)std::fputs("vn-gateway: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("vn-gateway: unexpected error\n", stderr);
    }
    return 1;
}
