#include "vnsl/can/frame.hpp"

#include <algorithm>
#include <charconv>
#include <format>

namespace vnsl::can {
namespace {

constexpr std::uint64_t kMaxSeconds = 32503680000ULL;  // year 3000: rejects absurd timestamps before overflow

bool parse_hex_u32(std::string_view s, std::uint32_t& out) {
    if (s.empty() || s.size() > 8) return false;
    std::uint32_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (ec != std::errc{} || p != s.data() + s.size()) return false;
    out = v;
    return true;
}

template <typename T>
bool parse_dec(std::string_view s, T& out) {
    if (s.empty()) return false;
    T v{};
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v, 10);
    if (ec != std::errc{} || p != s.data() + s.size()) return false;
    out = v;
    return true;
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// "1606390200.265340" -> microseconds. Requires 1..6 fraction digits.
bool parse_seconds_dot_micros(std::string_view s, std::uint64_t& out) {
    const auto dot = s.find('.');
    if (dot == std::string_view::npos) return false;
    std::uint64_t sec = 0;
    if (!parse_dec(s.substr(0, dot), sec) || sec > kMaxSeconds) return false;
    const auto frac = s.substr(dot + 1);
    if (frac.empty() || frac.size() > 6) return false;
    std::uint64_t f = 0;
    if (!parse_dec(frac, f)) return false;
    for (std::size_t i = frac.size(); i < 6; ++i) f *= 10;
    out = sec * 1'000'000ULL + f;
    return true;
}

bool all_digits(std::string_view s) {
    return !s.empty() && std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; });
}

/// "2020-11-26 11:30:00.265340" (fraction optional, up to 6 digits) -> microseconds since epoch, as UTC.
bool parse_iso_datetime(std::string_view s, std::uint64_t& out) {
    if (s.size() < 19 || s[4] != '-' || s[7] != '-' || s[10] != ' ' || s[13] != ':' || s[16] != ':') return false;
    const auto yy = s.substr(0, 4);
    const auto mo = s.substr(5, 2);
    const auto dd = s.substr(8, 2);
    const auto hh = s.substr(11, 2);
    const auto mi = s.substr(14, 2);
    const auto ss = s.substr(17, 2);
    for (const auto f : {yy, mo, dd, hh, mi, ss})
        if (!all_digits(f)) return false;
    unsigned y = 0;
    unsigned m = 0;
    unsigned d = 0;
    unsigned h = 0;
    unsigned n = 0;
    unsigned sec = 0;
    parse_dec(yy, y);
    parse_dec(mo, m);
    parse_dec(dd, d);
    parse_dec(hh, h);
    parse_dec(mi, n);
    parse_dec(ss, sec);
    if (y < 1970 || y > 2999 || m < 1 || m > 12 || d < 1 || d > 31 || h > 23 || n > 59 || sec > 60) return false;
    std::uint64_t micros = 0;
    if (s.size() > 19) {
        if (s[19] != '.') return false;
        const auto frac = s.substr(20);
        if (frac.empty() || frac.size() > 6 || !all_digits(frac)) return false;
        parse_dec(frac, micros);
        for (std::size_t i = frac.size(); i < 6; ++i) micros *= 10;
    }
    const auto days = days_from_civil(y, m, d);
    const auto secs = static_cast<std::uint64_t>(days) * 86400ULL + h * 3600ULL + n * 60ULL + sec;
    out = secs * 1'000'000ULL + micros;
    return true;
}

}  // namespace

std::optional<Frame> parse_candump_line(std::string_view line, std::string* iface) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' ')) line.remove_suffix(1);
    if (line.size() < 2 || line.front() != '(') return std::nullopt;
    const auto close = line.find(')');
    if (close == std::string_view::npos) return std::nullopt;
    Frame f;
    if (!parse_seconds_dot_micros(line.substr(1, close - 1), f.t_us)) return std::nullopt;

    auto rest = line.substr(close + 1);
    if (rest.empty() || rest.front() != ' ') return std::nullopt;
    rest.remove_prefix(1);
    const auto sp = rest.find(' ');
    if (sp == std::string_view::npos || sp == 0) return std::nullopt;
    if (iface != nullptr) iface->assign(rest.substr(0, sp));
    rest = rest.substr(sp + 1);

    const auto hash = rest.find('#');
    if (hash == std::string_view::npos) return std::nullopt;
    const auto id_text = rest.substr(0, hash);
    if (id_text.size() == 8) {
        f.extended = true;
    } else if (id_text.size() == 3) {
        f.extended = false;
    } else {
        return std::nullopt;
    }
    if (!parse_hex_u32(id_text, f.id)) return std::nullopt;
    if (f.extended ? f.id > 0x1FFFFFFFU : f.id > 0x7FFU) return std::nullopt;

    const auto data_text = rest.substr(hash + 1);
    if (!data_text.empty() && (data_text.front() == '#' || data_text.front() == 'R' || data_text.front() == 'r'))
        return std::nullopt;  // CAN FD or remote frame: not used by J1939
    if (data_text.size() % 2 != 0 || data_text.size() > 16) return std::nullopt;
    f.dlc = static_cast<std::uint8_t>(data_text.size() / 2);
    for (std::size_t i = 0; i < f.dlc; ++i) {
        const int hi = hex_digit(data_text[2 * i]);
        const int lo = hex_digit(data_text[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        f.data[i] = static_cast<std::uint8_t>(hi * 16 + lo);
    }
    return f;
}

std::string format_candump(const Frame& frame, std::string_view iface) {
    std::string out = std::format("({}.{:06}) {}", frame.t_us / 1'000'000ULL, frame.t_us % 1'000'000ULL, iface);
    out += frame.extended ? std::format(" {:08X}#", frame.id) : std::format(" {:03X}#", frame.id);
    for (std::size_t i = 0; i < frame.dlc && i < frame.data.size(); ++i) out += std::format("{:02X}", frame.data[i]);
    return out;
}

std::optional<Frame> parse_turku_csv_line(std::string_view line) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.remove_suffix(1);
    std::array<std::string_view, 11> fields{};
    std::size_t count = 0;
    while (true) {
        const auto semi = line.find(';');
        if (count == fields.size()) return std::nullopt;  // too many fields
        fields[count++] = line.substr(0, semi);
        if (semi == std::string_view::npos) break;
        line.remove_prefix(semi + 1);
    }
    if (count < 3) return std::nullopt;

    Frame f;
    if (!parse_iso_datetime(fields[0], f.t_us)) return std::nullopt;
    auto id_text = fields[1];
    if (id_text.size() < 3 || id_text[0] != '0' || (id_text[1] != 'x' && id_text[1] != 'X')) return std::nullopt;
    id_text.remove_prefix(2);
    if (!parse_hex_u32(id_text, f.id)) return std::nullopt;
    // Every frame in this dataset is a J1939 (29-bit) frame; an identifier above 0x7FF proves it,
    // and the dataset has no 11-bit traffic, so all rows are treated as extended.
    if (f.id > 0x1FFFFFFFU) return std::nullopt;
    f.extended = true;
    unsigned dlc = 0;
    if (!parse_dec(fields[2], dlc) || dlc > 8 || count != 3 + dlc) return std::nullopt;
    f.dlc = static_cast<std::uint8_t>(dlc);
    for (std::size_t i = 0; i < dlc; ++i) {
        unsigned b = 0;
        if (!parse_dec(fields[3 + i], b) || b > 255) return std::nullopt;
        f.data[i] = static_cast<std::uint8_t>(b);
    }
    return f;
}

}  // namespace vnsl::can
