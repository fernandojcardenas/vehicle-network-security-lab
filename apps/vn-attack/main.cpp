// vn-attack: splices a labelled attack into a recorded CAN log, for evaluating vn-ids.
//
//   vn-attack IN.log --attack flood|spoof|replay|jump|hijack --start S --duration S
//             [--out OUT.log] [--labels OUT.labels] [--seed N]
//
// Reads a candump -l log, injects the attack over [start, start+duration) seconds (measured
// from the log's first frame), and writes the merged log sorted by time. The labels file
// records the attack window, which is the ground truth tools/evaluate_ids.py scores against.

#include <cstdint>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "vnsl/can/frame.hpp"
#include "vnsl/ids/attack.hpp"

namespace {

int run(int argc, char** argv) {
    std::string in_path;
    std::string out_path;
    std::string labels_path;
    std::string attack_name;
    double start_s = 0;
    double duration_s = 0;
    std::uint64_t seed = 1;
    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--attack" && i + 1 < argc) attack_name = argv[++i];
        else if (a == "--start" && i + 1 < argc) start_s = std::stod(argv[++i]);
        else if (a == "--duration" && i + 1 < argc) duration_s = std::stod(argv[++i]);
        else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
        else if (a == "--labels" && i + 1 < argc) labels_path = argv[++i];
        else if (a == "--seed" && i + 1 < argc) seed = std::stoull(argv[++i]);
        else if (!a.empty() && a[0] != '-') in_path = a;
        else { std::cerr << "vn-attack: unknown argument " << a << '\n'; return 2; }
    }
    vnsl::ids::AttackType type;
    if (!vnsl::ids::parse_attack_type(attack_name, type) || duration_s <= 0) {
        std::cerr << "usage: vn-attack IN.log --attack flood|spoof|replay|jump|hijack --start S --duration S "
                     "[--out OUT.log] [--labels OUT.labels] [--seed N]\n";
        return 2;
    }

    std::ifstream in(in_path, std::ios::binary);
    if (!in) { std::cerr << "vn-attack: cannot open " << in_path << '\n'; return 1; }
    std::vector<vnsl::can::Frame> frames;
    std::string line;
    std::string iface = "can0";
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::string got;
        if (auto f = vnsl::can::parse_candump_line(line, &got)) { frames.push_back(*f); iface = got; }
    }
    if (frames.empty()) { std::cerr << "vn-attack: no frames in " << in_path << '\n'; return 1; }

    const std::uint64_t t0 = frames.front().t_us;
    const auto result = vnsl::ids::inject_attack(frames, type, t0 + static_cast<std::uint64_t>(start_s * 1e6),
                                                 static_cast<std::uint64_t>(duration_s * 1e6), seed);

    std::ofstream out_file;
    if (!out_path.empty()) { out_file.open(out_path); if (!out_file) { std::cerr << "vn-attack: cannot write " << out_path << '\n'; return 1; } }
    std::ostream& out = out_path.empty() ? std::cout : out_file;
    std::ios::sync_with_stdio(false);
    for (const auto& f : result.frames) out << vnsl::can::format_candump(f, iface) << '\n';
    out.flush();

    for (const auto& w : result.windows) {
        std::cerr << "vn-attack: " << vnsl::ids::attack_type_name(w.type) << " injected " << w.injected_frames
                  << " frames over [" << static_cast<double>(w.start_us - t0) / 1e6 << ", "
                  << static_cast<double>(w.end_us - t0) / 1e6 << ") s\n";
        if (!labels_path.empty()) {
            std::ofstream lf(labels_path);
            lf << "# attack windows (microseconds since epoch)\n";
            for (const auto& win : result.windows)
                lf << "window " << vnsl::ids::attack_type_name(win.type) << ' ' << win.start_us << ' ' << win.end_us
                   << ' ' << win.injected_frames << '\n';
        }
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        (void)std::fputs("vn-attack: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("vn-attack: unexpected error\n", stderr);
    }
    return 1;
}
