#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace vnsl::j1939 {

/// How to read one parameter (SPN) out of a parameter group's payload.
///
/// Bits are counted the J1939 way: bit 0 is the least significant bit of byte 1, and
/// multi-byte values are little-endian. `start_bit = (byte - 1) * 8 + (bit - 1)`.
struct SpnDef {
    std::uint32_t spn = 0;
    std::uint32_t pgn = 0;
    std::string_view name;
    std::string_view unit;  ///< empty for a state (discrete) parameter
    std::uint16_t start_bit = 0;
    std::uint8_t length = 0;  ///< bits, 1..32
    double scale = 1.0;
    double offset = 0.0;

    [[nodiscard]] constexpr bool discrete() const { return unit.empty(); }
};

/// J1939-71 reserves the top of every parameter's range: the highest values mean
/// "not available" and the next band means "error indicator".
enum class Status : std::uint8_t {
    Valid,
    NotAvailable,  ///< the sender does not support or does not have this value
    Error,         ///< the sender has the parameter but its sensor or source has failed
    Reserved,      ///< a value SAE reserves for future definitions; never sent by a correct ECU
    Missing,       ///< the payload is too short to contain the parameter
};

struct SignalValue {
    const SpnDef* def = nullptr;
    Status status = Status::Missing;
    std::uint32_t raw = 0;
    double value = 0.0;  ///< raw * scale + offset; meaningful only when status == Valid
};

/// The parameters this library knows: 92 public, widely documented SPNs from the
/// FMS-Standard parameter groups plus a few common powertrain groups.
std::span<const SpnDef> spn_table();

/// Short name of a parameter group ("EEC1"), or an empty view if not known.
std::string_view pgn_name(std::uint32_t pgn);

/// Classifies a raw value of a parameter `length_bits` wide (see Status).
Status classify(std::uint32_t raw, std::uint8_t length_bits, bool discrete);

/// Extracts `length` bits starting at `start_bit` (J1939 bit order). Returns nullopt if the
/// payload is too short.
std::optional<std::uint32_t> extract_bits(std::span<const std::uint8_t> data, std::uint16_t start_bit,
                                          std::uint8_t length);

/// Decodes every known parameter of `pgn` from `data`.
std::vector<SignalValue> decode_signals(std::uint32_t pgn, std::span<const std::uint8_t> data);

/// One active diagnostic trouble code from DM1.
struct Dtc {
    std::uint32_t spn = 0;  ///< 19 bits: which parameter is faulty
    std::uint8_t fmi = 0;   ///< 5 bits: failure mode identifier
    std::uint8_t occurrences = 0;  ///< 7 bits; 127 means "not available"
    bool spn_conversion_method = false;
    friend bool operator==(const Dtc&, const Dtc&) = default;
};

/// DM1 (PGN 65226): lamp states and active trouble codes.
struct Dm1 {
    std::uint8_t malfunction_lamp = 3;  ///< 2-bit states: 0 off, 1 on, 2 error, 3 not available
    std::uint8_t red_stop_lamp = 3;
    std::uint8_t amber_warning_lamp = 3;
    std::uint8_t protect_lamp = 3;
    std::vector<Dtc> dtcs;
};

/// Decodes DM1. Returns nullopt if shorter than 6 bytes or if the trouble-code area is not a
/// whole number of 4-byte codes (ignoring 0xFF padding). The "no active codes" pattern
/// (SPN 0, FMI 0) yields an empty list.
std::optional<Dm1> decode_dm1(std::span<const std::uint8_t> data);

/// Time/Date (PGN 65254) as a calendar time.
///
/// The day field is not linear: it counts quarter days, and raw values 1-4 all mean the first
/// day of the month, 5-8 the second, and so on (raw 0 is "null"). A plain `raw * 0.25` gives
/// 25.5 for the 26th, which is why this helper exists.
struct TimeDate {
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    double second = 0;  ///< 0.25 s resolution
    std::optional<int> local_offset_minutes;  ///< local hour and minute offsets combined, if sent
};

/// Decodes Time/Date; nullopt if shorter than 6 bytes or any date/time field is not a valid
/// value (not available, error indicator, out of range, or day 0).
std::optional<TimeDate> decode_time_date(std::span<const std::uint8_t> data);

/// The 64-bit NAME an ECU sends in Address Claimed (PGN 60928).
struct Name {
    std::uint32_t identity_number = 0;  ///< 21 bits
    std::uint16_t manufacturer_code = 0;  ///< 11 bits
    std::uint8_t ecu_instance = 0;        ///< 3 bits
    std::uint8_t function_instance = 0;   ///< 5 bits
    std::uint8_t function = 0;            ///< 8 bits
    std::uint8_t vehicle_system = 0;      ///< 7 bits
    std::uint8_t vehicle_system_instance = 0;  ///< 4 bits
    std::uint8_t industry_group = 0;      ///< 3 bits
    bool arbitrary_address_capable = false;
    std::uint64_t raw = 0;
};

/// Decodes a NAME from an 8-byte Address Claimed payload; nullopt if shorter.
std::optional<Name> decode_name(std::span<const std::uint8_t> data);

}  // namespace vnsl::j1939
