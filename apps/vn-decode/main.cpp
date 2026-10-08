// vn-decode: reads a CAN log (can-utils candump -l, or the Turku truck CSV), reassembles
// J1939 transport-protocol transfers and decodes the parameters this library knows.
//
//   vn-decode [--format auto|candump|turku] [--json | --summary | --candump] [FILE|-]
//
//   --json      one JSON object per J1939 message (default)
//   --summary   per parameter group and source: count, mean period; transport counters
//   --candump   re-emit the input as a candump -l log (for replay with canplayer)

#include <cstdint>
#include <cstdio>
#include <exception>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "vnsl/can/frame.hpp"
#include "vnsl/j1939/signals.hpp"
#include "vnsl/j1939/transport.hpp"

namespace {

using vnsl::can::Frame;
namespace j1939 = vnsl::j1939;

enum class Format : std::uint8_t { Auto, Candump, Turku };
enum class Mode : std::uint8_t { Json, Summary, Candump };

void usage() {
    std::cerr << "usage: vn-decode [--format auto|candump|turku] [--json|--summary|--candump] [FILE|-]\n";
}

std::string_view status_text(j1939::Status s) {
    switch (s) {
        case j1939::Status::Valid:
            return "valid";
        case j1939::Status::NotAvailable:
            return "n/a";
        case j1939::Status::Error:
            return "error";
        case j1939::Status::Reserved:
            return "reserved";
        case j1939::Status::Missing:
            return "missing";
    }
    return "?";
}

void print_json(const j1939::Message& m) {
    std::string out = std::format(R"({{"t":{}.{:06},"pri":{},"pgn":{},"sa":{},"da":{},"tp":{},"data":")",
                                  m.t_us / 1'000'000ULL, m.t_us % 1'000'000ULL, m.priority, m.pgn, m.sa, m.da,
                                  m.multipacket ? "true" : "false");
    for (const auto b : m.data) out += std::format("{:02X}", b);
    out += '"';
    const auto name = j1939::pgn_name(m.pgn);
    if (!name.empty()) out += std::format(R"(,"name":"{}")", name);
    const auto signals = j1939::decode_signals(m.pgn, m.data);
    if (!signals.empty()) {
        out += R"(,"spn":{)";
        bool first = true;
        for (const auto& s : signals) {
            if (!first) out += ',';
            first = false;
            if (s.status == j1939::Status::Valid) {
                // 10 significant digits keep every scale in the table exact (multiples of 1/512 etc.).
                out += std::format(R"("{}":{:.10g})", s.def->spn, s.value);
            } else {
                out += std::format(R"("{}":"{}")", s.def->spn, status_text(s.status));
            }
        }
        out += '}';
    }
    if (m.pgn == 65254) {
        const auto td = j1939::decode_time_date(m.data);
        if (td.has_value()) {
            out += std::format(R"(,"time":"{:04}-{:02}-{:02}T{:02}:{:02}:{:05.2f}Z")", td->year, td->month, td->day,
                               td->hour, td->minute, td->second);
        }
    }
    if (m.pgn == j1939::kPgnDm1) {
        const auto dm = j1939::decode_dm1(m.data);
        if (dm.has_value()) {
            out += R"(,"dtc":[)";
            bool first = true;
            for (const auto& d : dm->dtcs) {
                out += std::format(R"({}{{"spn":{},"fmi":{},"oc":{}}})", first ? "" : ",", d.spn, d.fmi, d.occurrences);
                first = false;
            }
            out += ']';
        }
    }
    out += "}\n";
    std::cout << out;
}

struct PgnSourceStats {
    std::uint64_t count = 0;
    std::uint64_t multipacket = 0;
    std::uint64_t last_us = 0;
    double sum_gap_ms = 0;  // gaps under 5 s only, so log pauses do not distort the period
    std::uint64_t gaps = 0;
};

void print_summary(const std::map<std::pair<std::uint32_t, std::uint8_t>, PgnSourceStats>& table,
                   const j1939::TransportStats& tp, std::uint64_t frames, std::uint64_t unparsed) {
    std::cout << std::format("{:<7} {:<6} {:<4} {:>9} {:>5} {:>12}\n", "PGN", "name", "SA", "messages", "TP",
                             "period ms");
    for (const auto& [key, s] : table) {
        const std::string period =
            s.gaps ? std::format("{:.1f}", s.sum_gap_ms / static_cast<double>(s.gaps)) : std::string("-");
        std::cout << std::format("{:<7} {:<6} {:<4} {:>9} {:>5} {:>12}\n", key.first, j1939::pgn_name(key.first),
                                 key.second, s.count, s.multipacket, period);
    }
    std::cout << std::format("\nframes {}, unparsed lines {}\n", frames, unparsed);
    std::cout << std::format("single-frame messages {}\n", tp.single_frame_messages);
    std::cout << std::format(
        "BAM started {}, completed {}; RTS started {}, completed {}; CTS {}, EndOfMsgAck {}\n", tp.bam_started,
        tp.completed_bam, tp.rts_started, tp.completed_cmdt, tp.cts, tp.end_of_msg_ack);
    std::cout << std::format(
        "transport problems: timeouts {}, sequence errors {}, bad announcements {}, aborts {}, replaced {}, "
        "orphan data {}, malformed {}, rejected (too many sessions) {}\n",
        tp.timeouts, tp.sequence_errors, tp.bad_announcements, tp.aborts_seen, tp.replaced_sessions, tp.orphan_data,
        tp.malformed_tp_frames, tp.rejected_too_many_sessions);
}

}  // namespace

namespace {

int run(int argc, char** argv) {
    Format format = Format::Auto;
    Mode mode = Mode::Json;
    std::string path = "-";
    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--json") {
            mode = Mode::Json;
        } else if (a == "--summary") {
            mode = Mode::Summary;
        } else if (a == "--candump") {
            mode = Mode::Candump;
        } else if (a == "--format" && i + 1 < argc) {
            const std::string_view f = argv[++i];
            if (f == "auto") {
                format = Format::Auto;
            } else if (f == "candump") {
                format = Format::Candump;
            } else if (f == "turku") {
                format = Format::Turku;
            } else {
                usage();
                return 2;
            }
        } else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (!a.empty() && a[0] == '-' && a != "-") {
            usage();
            return 2;
        } else {
            path = a;
        }
    }

    std::ifstream file;
    if (path != "-") {
        file.open(path, std::ios::binary);
        if (!file) {
            std::cerr << "vn-decode: cannot open " << path << '\n';
            return 1;
        }
    }
    std::istream& in = path == "-" ? std::cin : file;
    std::ios::sync_with_stdio(false);

    j1939::Reassembler reassembler;
    std::map<std::pair<std::uint32_t, std::uint8_t>, PgnSourceStats> table;
    std::uint64_t frames = 0;
    std::uint64_t unparsed = 0;
    std::string line;
    std::string iface = "can0";
    bool first_line = true;

    const auto on_message = [&](const j1939::Message& m) {
        if (mode == Mode::Json) {
            print_json(m);
            return;
        }
        auto& s = table[{m.pgn, m.sa}];
        if (s.count > 0) {
            const double gap_ms = static_cast<double>(m.t_us - s.last_us) / 1000.0;
            if (m.t_us >= s.last_us && gap_ms < 5000.0) {
                s.sum_gap_ms += gap_ms;
                ++s.gaps;
            }
        }
        s.last_us = m.t_us;
        ++s.count;
        if (m.multipacket) ++s.multipacket;
    };

    while (std::getline(in, line)) {
        if (first_line && format == Format::Auto)
            format = (!line.empty() && line[0] == '(') ? Format::Candump : Format::Turku;
        const bool header = first_line && format == Format::Turku && line.starts_with("timestamp");
        first_line = false;
        if (header || line.empty() || line == "\r") continue;
        const std::optional<Frame> f =
            format == Format::Candump ? vnsl::can::parse_candump_line(line, &iface) : vnsl::can::parse_turku_csv_line(line);
        if (!f) {
            ++unparsed;
            continue;
        }
        ++frames;
        if (mode == Mode::Candump) {
            std::cout << vnsl::can::format_candump(*f, iface) << '\n';
            continue;
        }
        reassembler.on_frame(*f, on_message);
    }
    if (mode == Mode::Summary) print_summary(table, reassembler.stats(), frames, unparsed);
    if (unparsed > 0) std::cerr << "vn-decode: " << unparsed << " lines could not be parsed\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        (void)std::fputs("vn-decode: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("vn-decode: unexpected error\n", stderr);
    }
    return 1;
}
