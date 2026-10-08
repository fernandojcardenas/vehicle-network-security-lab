#pragma once

#include <cstdint>

namespace vnsl::j1939 {

inline constexpr std::uint8_t kGlobalAddress = 0xFF;  ///< destination "all nodes"
inline constexpr std::uint8_t kNullAddress = 0xFE;    ///< source of a node that has no address yet

inline constexpr std::uint32_t kPgnRequest = 0xEA00;       ///< 59904
inline constexpr std::uint32_t kPgnTpDataTransfer = 0xEB00;  ///< 60160 TP.DT
inline constexpr std::uint32_t kPgnTpConnection = 0xEC00;    ///< 60416 TP.CM
inline constexpr std::uint32_t kPgnAddressClaimed = 0xEE00;  ///< 60928
inline constexpr std::uint32_t kPgnDm1 = 0xFECA;             ///< 65226 active diagnostic trouble codes

/// The fields of a 29-bit J1939 identifier.
///
/// Layout (bit 28 first): priority (3) | EDP (1) | DP (1) | PF (8) | PS (8) | SA (8).
/// When PF < 240 the frame is PDU1: PS is the destination address and is not part of the PGN.
/// When PF >= 240 the frame is PDU2: PS is a group extension, part of the PGN, and the
/// message is always broadcast.
struct Id {
    std::uint8_t priority = 0;  ///< 0 (highest) .. 7
    std::uint32_t pgn = 0;      ///< 18-bit parameter group number (EDP, DP, PF and, for PDU2, PS)
    std::uint8_t sa = 0;        ///< source address
    std::uint8_t da = kGlobalAddress;  ///< destination address (kGlobalAddress for PDU2)

    [[nodiscard]] constexpr bool pdu1() const { return ((pgn >> 8) & 0xFF) < 240; }
    friend constexpr bool operator==(const Id&, const Id&) = default;
};

/// Splits a 29-bit identifier. Bits above 28 are ignored.
constexpr Id decode_id(std::uint32_t id29) {
    Id id;
    id.priority = static_cast<std::uint8_t>((id29 >> 26) & 0x7);
    id.sa = static_cast<std::uint8_t>(id29 & 0xFF);
    const std::uint32_t pf = (id29 >> 16) & 0xFF;
    const std::uint32_t ps = (id29 >> 8) & 0xFF;
    const std::uint32_t edp_dp = (id29 >> 24) & 0x3;
    if (pf < 240) {
        id.pgn = (edp_dp << 16) | (pf << 8);
        id.da = static_cast<std::uint8_t>(ps);
    } else {
        id.pgn = (edp_dp << 16) | (pf << 8) | ps;
        id.da = kGlobalAddress;
    }
    return id;
}

/// Builds a 29-bit identifier. For a PDU1 PGN the destination goes into PS (the PGN's low
/// byte must be 0); for a PDU2 PGN the destination is ignored.
constexpr std::uint32_t encode_id(std::uint8_t priority, std::uint32_t pgn, std::uint8_t sa,
                                  std::uint8_t da = kGlobalAddress) {
    std::uint32_t id = (static_cast<std::uint32_t>(priority & 0x7) << 26) | ((pgn & 0x3FFFF) << 8) | sa;
    if (((pgn >> 8) & 0xFF) < 240) id = (id & ~0xFF00U) | (static_cast<std::uint32_t>(da) << 8);
    return id;
}

}  // namespace vnsl::j1939
