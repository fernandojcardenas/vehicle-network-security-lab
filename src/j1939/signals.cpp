#include "vnsl/j1939/signals.hpp"

#include <array>
#include <cmath>

namespace vnsl::j1939 {
namespace {

// Positions: start bit = (byte - 1) * 8 + (bit - 1); see SpnDef.
// Sources: the FMS-Standard interface description (v02.00, public) for the FMS groups, and
// public J1939-71 summaries for the rest. Positions that public sources disagreed on, or did
// not state, are checked against real truck traffic in tools/check_consistency.py.
constexpr std::array kTable{
    // EEC1 61444 Electronic Engine Controller 1
    SpnDef{899, 61444, "Engine torque mode", "", 0, 4},
    SpnDef{512, 61444, "Driver's demand engine percent torque", "%", 8, 8, 1, -125},
    SpnDef{513, 61444, "Actual engine percent torque", "%", 16, 8, 1, -125},
    SpnDef{190, 61444, "Engine speed", "rpm", 24, 16, 0.125, 0},
    SpnDef{1483, 61444, "Source address of controlling device for engine control", "", 40, 8},
    SpnDef{1675, 61444, "Engine starter mode", "", 48, 4},
    SpnDef{2432, 61444, "Engine demand percent torque", "%", 56, 8, 1, -125},
    // EEC2 61443 Electronic Engine Controller 2
    SpnDef{558, 61443, "Accelerator pedal 1 low idle switch", "", 0, 2},
    SpnDef{559, 61443, "Accelerator pedal kickdown switch", "", 2, 2},
    SpnDef{91, 61443, "Accelerator pedal position 1", "%", 8, 8, 0.4, 0},
    SpnDef{92, 61443, "Engine percent load at current speed", "%", 16, 8, 1, 0},
    SpnDef{974, 61443, "Remote accelerator pedal position", "%", 24, 8, 0.4, 0},
    // ETC1 61442 Electronic Transmission Controller 1
    SpnDef{560, 61442, "Transmission driveline engaged", "", 0, 2},
    SpnDef{573, 61442, "Torque converter lockup engaged", "", 2, 2},
    SpnDef{574, 61442, "Transmission shift in process", "", 4, 2},
    SpnDef{191, 61442, "Transmission output shaft speed", "rpm", 8, 16, 0.125, 0},
    SpnDef{522, 61442, "Percent clutch slip", "%", 24, 8, 0.4, 0},
    SpnDef{161, 61442, "Transmission input shaft speed", "rpm", 40, 16, 0.125, 0},
    SpnDef{1482, 61442, "Source address of controlling device for transmission control", "", 56, 8},
    // ETC2 61445 Electronic Transmission Controller 2
    SpnDef{524, 61445, "Transmission selected gear", "gear", 0, 8, 1, -125},
    SpnDef{526, 61445, "Transmission actual gear ratio", "ratio", 8, 16, 0.001, 0},
    SpnDef{523, 61445, "Transmission current gear", "gear", 24, 8, 1, -125},
    // EBC1 61441 Electronic Brake Controller 1
    SpnDef{561, 61441, "ASR engine control active", "", 0, 2},
    SpnDef{562, 61441, "ASR brake control active", "", 2, 2},
    SpnDef{563, 61441, "ABS active", "", 4, 2},
    SpnDef{1121, 61441, "EBS brake switch", "", 6, 2},
    SpnDef{521, 61441, "Brake pedal position", "%", 8, 8, 0.4, 0},
    // CCVS1 65265 Cruise Control / Vehicle Speed 1
    SpnDef{69, 65265, "Two speed axle switch", "", 0, 2},
    SpnDef{70, 65265, "Parking brake switch", "", 2, 2},
    SpnDef{84, 65265, "Wheel-based vehicle speed", "km/h", 8, 16, 1.0 / 256.0, 0},
    SpnDef{595, 65265, "Cruise control active", "", 24, 2},
    SpnDef{596, 65265, "Cruise control enable switch", "", 26, 2},
    SpnDef{597, 65265, "Brake switch", "", 28, 2},
    SpnDef{598, 65265, "Clutch switch", "", 30, 2},
    SpnDef{86, 65265, "Cruise control set speed", "km/h", 40, 8, 1, 0},
    SpnDef{976, 65265, "PTO governor state", "", 48, 5},
    // TCO1 65132 Tachograph
    SpnDef{1612, 65132, "Driver 1 working state", "", 0, 3},
    SpnDef{1613, 65132, "Driver 2 working state", "", 3, 3},
    SpnDef{1611, 65132, "Vehicle motion", "", 6, 2},
    SpnDef{1617, 65132, "Driver 1 time related states", "", 8, 4},
    SpnDef{1615, 65132, "Driver card, driver 1", "", 12, 2},
    SpnDef{1614, 65132, "Vehicle overspeed", "", 14, 2},
    SpnDef{1618, 65132, "Driver 2 time related states", "", 16, 4},
    SpnDef{1616, 65132, "Driver card, driver 2", "", 20, 2},
    SpnDef{1622, 65132, "System event", "", 24, 2},
    SpnDef{1621, 65132, "Handling information", "", 26, 2},
    SpnDef{1620, 65132, "Tachograph performance", "", 28, 2},
    SpnDef{1619, 65132, "Direction indicator", "", 30, 2},
    SpnDef{1623, 65132, "Tachograph output shaft speed", "rpm", 32, 16, 0.125, 0},
    SpnDef{1624, 65132, "Tachograph vehicle speed", "km/h", 48, 16, 1.0 / 256.0, 0},
    // ET1 65262 Engine Temperature 1
    SpnDef{110, 65262, "Engine coolant temperature", "degC", 0, 8, 1, -40},
    SpnDef{174, 65262, "Engine fuel temperature 1", "degC", 8, 8, 1, -40},
    SpnDef{175, 65262, "Engine oil temperature 1", "degC", 16, 16, 0.03125, -273},
    SpnDef{176, 65262, "Engine turbocharger oil temperature", "degC", 32, 16, 0.03125, -273},
    SpnDef{52, 65262, "Engine intercooler temperature", "degC", 48, 8, 1, -40},
    // EFL/P1 65263 Engine Fluid Level/Pressure 1
    SpnDef{94, 65263, "Engine fuel delivery pressure", "kPa", 0, 8, 4, 0},
    SpnDef{98, 65263, "Engine oil level", "%", 16, 8, 0.4, 0},
    SpnDef{100, 65263, "Engine oil pressure", "kPa", 24, 8, 4, 0},
    SpnDef{109, 65263, "Engine coolant pressure", "kPa", 48, 8, 2, 0},
    SpnDef{111, 65263, "Engine coolant level", "%", 56, 8, 0.4, 0},
    // LFE1 65266 Fuel Economy (Liquid)
    SpnDef{183, 65266, "Engine fuel rate", "L/h", 0, 16, 0.05, 0},
    SpnDef{184, 65266, "Engine instantaneous fuel economy", "km/L", 16, 16, 1.0 / 512.0, 0},
    SpnDef{185, 65266, "Engine average fuel economy", "km/L", 32, 16, 1.0 / 512.0, 0},
    SpnDef{51, 65266, "Engine throttle valve 1 position", "%", 48, 8, 0.4, 0},
    // AMB 65269 Ambient Conditions
    SpnDef{108, 65269, "Barometric pressure", "kPa", 0, 8, 0.5, 0},
    SpnDef{170, 65269, "Cab interior temperature", "degC", 8, 16, 0.03125, -273},
    SpnDef{171, 65269, "Ambient air temperature", "degC", 24, 16, 0.03125, -273},
    SpnDef{172, 65269, "Engine air inlet temperature", "degC", 40, 8, 1, -40},
    SpnDef{79, 65269, "Road surface temperature", "degC", 48, 16, 0.03125, -273},
    // VDHR 65217 High Resolution Vehicle Distance
    SpnDef{917, 65217, "High resolution total vehicle distance", "km", 0, 32, 0.005, 0},
    SpnDef{918, 65217, "High resolution trip distance", "km", 32, 32, 0.005, 0},
    // HOURS 65253 Engine Hours, Revolutions
    SpnDef{247, 65253, "Engine total hours of operation", "h", 0, 32, 0.05, 0},
    SpnDef{249, 65253, "Engine total revolutions", "r", 32, 32, 1000, 0},
    // LFC 65257 Fuel Consumption (Liquid)
    SpnDef{182, 65257, "Engine trip fuel", "L", 0, 32, 0.5, 0},
    SpnDef{250, 65257, "Engine total fuel used", "L", 32, 32, 0.5, 0},
    // HRLFC 64777 High Resolution Fuel Consumption (Liquid)
    SpnDef{5053, 64777, "High resolution engine trip fuel", "L", 0, 32, 0.001, 0},
    SpnDef{5054, 64777, "High resolution engine total fuel used", "L", 32, 32, 0.001, 0},
    // DD 65276 Dash Display
    SpnDef{80, 65276, "Washer fluid level", "%", 0, 8, 0.4, 0},
    SpnDef{96, 65276, "Fuel level 1", "%", 8, 8, 0.4, 0},
    // TD 65254 Time/Date
    SpnDef{959, 65254, "Seconds", "s", 0, 8, 0.25, 0},
    SpnDef{960, 65254, "Minutes", "min", 8, 8, 1, 0},
    SpnDef{961, 65254, "Hours", "h", 16, 8, 1, 0},
    SpnDef{963, 65254, "Month", "month", 24, 8, 1, 0},
    SpnDef{962, 65254, "Day", "day", 32, 8, 0.25, 0},
    SpnDef{964, 65254, "Year", "year", 40, 8, 1, 1985},
    SpnDef{1601, 65254, "Local minute offset", "min", 48, 8, 1, -125},
    SpnDef{1602, 65254, "Local hour offset", "h", 56, 8, 1, -125},
    // VEP1 65271 Vehicle Electrical Power 1
    SpnDef{114, 65271, "Net battery current", "A", 0, 8, 1, -125},
    SpnDef{115, 65271, "Alternator current", "A", 8, 8, 1, 0},
    SpnDef{167, 65271, "Charging system potential", "V", 16, 16, 0.05, 0},
    SpnDef{168, 65271, "Battery potential / power input 1", "V", 32, 16, 0.05, 0},
    SpnDef{158, 65271, "Keyswitch battery potential", "V", 48, 16, 0.05, 0},
};

struct PgnNameEntry {
    std::uint32_t pgn;
    std::string_view name;
};

constexpr std::array kPgnNames{
    PgnNameEntry{0, "TSC1"},        PgnNameEntry{59392, "ACKM"},   PgnNameEntry{59904, "RQST"},
    PgnNameEntry{60160, "TP.DT"},   PgnNameEntry{60416, "TP.CM"},  PgnNameEntry{60928, "AC"},
    PgnNameEntry{61441, "EBC1"},    PgnNameEntry{61442, "ETC1"},   PgnNameEntry{61443, "EEC2"},
    PgnNameEntry{61444, "EEC1"},    PgnNameEntry{61445, "ETC2"},   PgnNameEntry{64777, "HRLFC"},
    PgnNameEntry{65132, "TCO1"},    PgnNameEntry{65217, "VDHR"},   PgnNameEntry{65226, "DM1"},
    PgnNameEntry{65253, "HOURS"},   PgnNameEntry{65254, "TD"},     PgnNameEntry{65257, "LFC"},
    PgnNameEntry{65262, "ET1"},     PgnNameEntry{65263, "EFL/P1"}, PgnNameEntry{65265, "CCVS1"},
    PgnNameEntry{65266, "LFE1"},    PgnNameEntry{65269, "AMB"},    PgnNameEntry{65271, "VEP1"},
    PgnNameEntry{65276, "DD"},
};

}  // namespace

std::span<const SpnDef> spn_table() { return kTable; }

std::string_view pgn_name(std::uint32_t pgn) {
    for (const auto& e : kPgnNames)
        if (e.pgn == pgn) return e.name;
    return {};
}

Status classify(std::uint32_t raw, std::uint8_t length_bits, bool discrete) {
    if (length_bits == 0 || length_bits > 32) return Status::Missing;
    const std::uint32_t max = length_bits == 32 ? 0xFFFFFFFFU : ((1U << length_bits) - 1U);
    if (discrete || length_bits < 8) {
        // State fields: all ones = not available; for 2 bits and wider, all ones minus one = error.
        if (raw == max) return Status::NotAvailable;
        if (length_bits >= 2 && raw == max - 1) return Status::Error;
        return Status::Valid;
    }
    // Measured values: the top byte of the range is split into valid / reserved / error / n.a.
    // For 8 bits: 0..250 valid, 251..253 reserved, 254 error, 255 n.a.; wider fields scale the
    // same split by the most significant byte (e.g. 16 bits: up to 0xFAFF valid, 0xFExx error).
    const unsigned shift = length_bits - 8U;
    const std::uint32_t top = raw >> shift;
    if (length_bits % 8 != 0) {
        // Non-byte-multiple measured fields (rare): only the all-ones value is reserved.
        return raw == max ? Status::NotAvailable : Status::Valid;
    }
    if (top <= 0xFA) return Status::Valid;
    if (top == 0xFE) return Status::Error;
    if (top == 0xFF) return Status::NotAvailable;
    return Status::Reserved;
}

std::optional<std::uint32_t> extract_bits(std::span<const std::uint8_t> data, std::uint16_t start_bit,
                                          std::uint8_t length) {
    if (length == 0 || length > 32) return std::nullopt;
    const std::size_t end_bit = static_cast<std::size_t>(start_bit) + length;
    if (end_bit > data.size() * 8) return std::nullopt;
    std::uint64_t acc = 0;
    const std::size_t first = start_bit / 8;
    const std::size_t last = (end_bit - 1) / 8;
    for (std::size_t i = last + 1; i-- > first;) acc = (acc << 8) | data[i];
    acc >>= start_bit % 8;
    const std::uint64_t mask = (std::uint64_t{1} << length) - 1;
    return static_cast<std::uint32_t>(acc & mask);
}

std::vector<SignalValue> decode_signals(std::uint32_t pgn, std::span<const std::uint8_t> data) {
    std::vector<SignalValue> out;
    for (const auto& def : kTable) {
        if (def.pgn != pgn) continue;
        SignalValue v;
        v.def = &def;
        const auto raw = extract_bits(data, def.start_bit, def.length);
        if (!raw) {
            v.status = Status::Missing;
        } else {
            v.raw = *raw;
            v.status = classify(*raw, def.length, def.discrete());
            v.value = static_cast<double>(*raw) * def.scale + def.offset;
        }
        out.push_back(v);
    }
    return out;
}

bool insert_bits(std::span<std::uint8_t> data, std::uint16_t start_bit, std::uint8_t length, std::uint32_t raw) {
    if (length == 0 || length > 32) return false;
    const std::size_t end_bit = static_cast<std::size_t>(start_bit) + length;
    if (end_bit > data.size() * 8) return false;
    for (std::size_t i = 0; i < length; ++i) {
        const std::size_t bit = start_bit + i;
        const auto mask = static_cast<std::uint8_t>(1U << (bit % 8));
        if (((raw >> i) & 1U) != 0) {
            data[bit / 8] = static_cast<std::uint8_t>(data[bit / 8] | mask);
        } else {
            data[bit / 8] = static_cast<std::uint8_t>(data[bit / 8] & ~mask);
        }
    }
    return true;
}

namespace {

/// Largest raw value classify() calls Valid for a field of this width.
std::uint32_t max_valid_raw(std::uint8_t length, bool discrete) {
    const std::uint64_t all = (std::uint64_t{1} << length) - 1;
    if (discrete || length < 8 || length % 8 != 0) {
        if (length >= 2) return static_cast<std::uint32_t>(all - 2);
        return 0;
    }
    const unsigned shift = length - 8U;
    return static_cast<std::uint32_t>((std::uint64_t{0xFA} << shift) | ((std::uint64_t{1} << shift) - 1));
}

}  // namespace

std::array<std::uint8_t, 8> encode_signals(std::uint32_t pgn, std::span<const SignalInput> inputs) {
    std::array<std::uint8_t, 8> out{};
    out.fill(0xFF);
    for (const auto& in : inputs) {
        for (const auto& def : kTable) {
            if (def.pgn != pgn || def.spn != in.spn) continue;
            const std::uint32_t max = max_valid_raw(def.length, def.discrete());
            double raw = def.discrete() ? in.value : (in.value - def.offset) / def.scale;
            raw = std::nearbyint(raw);
            if (!(raw >= 0.0)) raw = 0.0;  // also catches NaN
            if (raw > static_cast<double>(max)) raw = static_cast<double>(max);
            insert_bits(out, def.start_bit, def.length, static_cast<std::uint32_t>(raw));
        }
    }
    return out;
}

std::vector<std::uint8_t> encode_dm1(const Dm1& dm) {
    std::vector<std::uint8_t> out;
    out.push_back(static_cast<std::uint8_t>((dm.protect_lamp & 3) | ((dm.amber_warning_lamp & 3) << 2) |
                                            ((dm.red_stop_lamp & 3) << 4) | ((dm.malfunction_lamp & 3) << 6)));
    out.push_back(0xFF);  // flash states: not available
    if (dm.dtcs.empty()) {
        out.insert(out.end(), {0, 0, 0, 0, 0xFF, 0xFF});
        return out;
    }
    for (const auto& d : dm.dtcs) {
        out.push_back(static_cast<std::uint8_t>(d.spn & 0xFF));
        out.push_back(static_cast<std::uint8_t>((d.spn >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((((d.spn >> 16) & 0x7) << 5) | (d.fmi & 0x1F)));
        out.push_back(static_cast<std::uint8_t>((d.spn_conversion_method ? 0x80 : 0) | (d.occurrences & 0x7F)));
    }
    if (out.size() < 8) out.resize(8, 0xFF);
    return out;
}

std::optional<Dm1> decode_dm1(std::span<const std::uint8_t> data) {
    if (data.size() < 6) return std::nullopt;
    Dm1 dm;
    dm.protect_lamp = data[0] & 0x3;
    dm.amber_warning_lamp = (data[0] >> 2) & 0x3;
    dm.red_stop_lamp = (data[0] >> 4) & 0x3;
    dm.malfunction_lamp = (data[0] >> 6) & 0x3;
    // A single-frame DM1 is padded to 8 bytes with 0xFF; strip trailing padding.
    std::size_t end = data.size();
    while (end > 6 && data[end - 1] == 0xFF) --end;
    if ((end - 2) % 4 != 0) return std::nullopt;
    for (std::size_t i = 2; i + 4 <= end; i += 4) {
        Dtc d;
        d.spn = static_cast<std::uint32_t>(data[i]) | (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                (static_cast<std::uint32_t>(data[i + 2] >> 5) << 16);
        d.fmi = data[i + 2] & 0x1F;
        d.occurrences = data[i + 3] & 0x7F;
        d.spn_conversion_method = (data[i + 3] & 0x80) != 0;
        const bool no_code = d.spn == 0 && d.fmi == 0;
        const bool all_ones = data[i] == 0xFF && data[i + 1] == 0xFF && data[i + 2] == 0xFF && data[i + 3] == 0xFF;
        if (!no_code && !all_ones) dm.dtcs.push_back(d);
    }
    return dm;
}

std::optional<TimeDate> decode_time_date(std::span<const std::uint8_t> data) {
    if (data.size() < 6) return std::nullopt;
    for (std::size_t i = 0; i < 6; ++i)
        if (classify(data[i], 8, false) != Status::Valid) return std::nullopt;
    const unsigned sec_q = data[0];
    const unsigned minute = data[1];
    const unsigned hour = data[2];
    const unsigned month = data[3];
    const unsigned day_q = data[4];
    if (sec_q > 239 || minute > 59 || hour > 23 || month < 1 || month > 12 || day_q < 1 || day_q > 124)
        return std::nullopt;
    TimeDate td;
    td.second = sec_q * 0.25;
    td.minute = static_cast<int>(minute);
    td.hour = static_cast<int>(hour);
    td.month = static_cast<int>(month);
    td.day = static_cast<int>((day_q + 3) / 4);
    td.year = 1985 + data[5];
    if (data.size() >= 8 && classify(data[6], 8, false) == Status::Valid &&
        classify(data[7], 8, false) == Status::Valid) {
        const int minutes = static_cast<int>(data[6]) - 125;
        const int hours = static_cast<int>(data[7]) - 125;
        if (minutes >= -59 && minutes <= 59 && hours >= -23 && hours <= 23)
            td.local_offset_minutes = hours * 60 + minutes;
    }
    return td;
}

std::optional<Name> decode_name(std::span<const std::uint8_t> data) {
    if (data.size() < 8) return std::nullopt;
    std::uint64_t raw = 0;
    for (std::size_t i = 8; i-- > 0;) raw = (raw << 8) | data[i];
    Name n;
    n.raw = raw;
    n.identity_number = static_cast<std::uint32_t>(raw & 0x1FFFFF);
    n.manufacturer_code = static_cast<std::uint16_t>((raw >> 21) & 0x7FF);
    n.ecu_instance = static_cast<std::uint8_t>((raw >> 32) & 0x7);
    n.function_instance = static_cast<std::uint8_t>((raw >> 35) & 0x1F);
    n.function = static_cast<std::uint8_t>((raw >> 40) & 0xFF);
    n.vehicle_system = static_cast<std::uint8_t>((raw >> 49) & 0x7F);
    n.vehicle_system_instance = static_cast<std::uint8_t>((raw >> 56) & 0xF);
    n.industry_group = static_cast<std::uint8_t>((raw >> 60) & 0x7);
    n.arbitrary_address_capable = (raw >> 63) != 0;
    return n;
}

}  // namespace vnsl::j1939
