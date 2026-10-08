// Tests against real traffic: a slice of the University of Turku heavy-duty truck CAN dataset
// (Renault T520, FMS interface, CC BY 4.0; see docs/data-sources.md).

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "vnsl/can/frame.hpp"
#include "vnsl/j1939/signals.hpp"
#include "vnsl/j1939/transport.hpp"

using namespace vnsl;

namespace {

struct Capture {
    std::vector<can::Frame> frames;
    std::size_t unparsed = 0;
};

const Capture& capture() {
    static const Capture c = [] {
        Capture out;
        std::ifstream in(VNSL_TESTDATA_DIR "/turku-truck-2020-11-26-slice.csv", std::ios::binary);
        std::string line;
        std::getline(in, line);  // header
        while (std::getline(in, line)) {
            if (const auto f = can::parse_turku_csv_line(line)) {
                out.frames.push_back(*f);
            } else {
                ++out.unparsed;
            }
        }
        return out;
    }();
    return c;
}

struct Decoded {
    std::vector<j1939::Message> messages;
    j1939::TransportStats stats;
};

Decoded decode_all() {
    Decoded d;
    j1939::Reassembler r;
    for (const auto& f : capture().frames) r.on_frame(f, [&](const j1939::Message& m) { d.messages.push_back(m); });
    d.stats = r.stats();
    return d;
}

}  // namespace

TEST(Capture, EveryRowParses) {
    EXPECT_EQ(capture().frames.size(), 15766u);
    EXPECT_EQ(capture().unparsed, 0u);
    EXPECT_TRUE(std::is_sorted(capture().frames.begin(), capture().frames.end(),
                               [](const auto& a, const auto& b) { return a.t_us < b.t_us; }));
}

TEST(Capture, TransportLayerAccountsForEveryFrame) {
    const auto d = decode_all();
    EXPECT_EQ(d.messages.size(), 15640u);  // same count as the can-j1939 cross-check
    EXPECT_EQ(d.stats.single_frame_messages, 15600u);
    EXPECT_EQ(d.stats.bam_started, 42u);
    EXPECT_EQ(d.stats.completed_bam, 40u);
    // The two unfinished transfers lost their last packet to the logger's two pauses
    // (98 s and 438 s) and were correctly timed out rather than completed or merged.
    EXPECT_EQ(d.stats.timeouts, 2u);
    EXPECT_EQ(d.stats.sequence_errors, 0u);
    EXPECT_EQ(d.stats.bad_announcements, 0u);
    EXPECT_EQ(d.stats.orphan_data, 0u);
    EXPECT_EQ(d.stats.malformed_tp_frames, 0u);
}

TEST(Capture, ReassembledTransfersHaveTheAnnouncedSizes) {
    const auto d = decode_all();
    std::map<std::uint32_t, std::size_t> by_pgn;
    for (const auto& m : d.messages) {
        if (!m.multipacket) continue;
        ++by_pgn[m.pgn];
        if (m.pgn == 65450) EXPECT_EQ(m.data.size(), 21u);
        if (m.pgn == 65260) EXPECT_GT(m.data.size(), 8u);  // vehicle identification (VIN); not printed
    }
    EXPECT_EQ(by_pgn[65450], 38u);
    EXPECT_EQ(by_pgn[65260], 2u);
}

TEST(Capture, TruckClockAgreesWithTheLogClock) {
    // Real frame: 2020-11-26 09:28:52.5 UTC in the truck's Time/Date message.
    const std::uint8_t first[] = {0xD2, 0x1C, 0x09, 0x0B, 0x66, 0x23, 0xFF, 0xFF};
    const auto td = j1939::decode_time_date(first);
    ASSERT_TRUE(td);
    EXPECT_EQ(td->year, 2020);
    EXPECT_EQ(td->month, 11);
    EXPECT_EQ(td->day, 26);  // raw 102 quarter-days: the 26th, not 25.5
    EXPECT_EQ(td->hour, 9);
    EXPECT_EQ(td->minute, 28);
    EXPECT_DOUBLE_EQ(td->second, 52.5);
    EXPECT_FALSE(td->local_offset_minutes);

    // Across the capture, log time minus truck time must stay constant to within the field's
    // 0.25 s resolution plus scheduling jitter. Any wrong field would break this.
    const auto d = decode_all();
    std::vector<double> offsets;
    std::size_t error_frames = 0;
    for (const auto& m : d.messages) {
        if (m.pgn != 65254) continue;
        const auto t = j1939::decode_time_date(m.data);
        if (!t) {
            ++error_frames;
            continue;
        }
        const double truck = static_cast<double>(can::days_from_civil(t->year, static_cast<unsigned>(t->month),
                                                                     static_cast<unsigned>(t->day))) * 86400.0 +
                             t->hour * 3600.0 + t->minute * 60.0 + t->second;
        offsets.push_back(static_cast<double>(m.t_us) / 1e6 - truck);
    }
    ASSERT_EQ(offsets.size(), 37u);
    EXPECT_EQ(error_frames, 3u);  // sent as "error indicator" just after each logger restart
    const auto [lo, hi] = std::minmax_element(offsets.begin(), offsets.end());
    EXPECT_LT(*hi - *lo, 0.5);
    // The log timestamps are Finnish local time (UTC+2) and the logger clock is ~68 s off the truck's.
    EXPECT_NEAR(*lo, 2 * 3600 + 67.6, 1.0);
}

TEST(Capture, ParkedTruckReportsNotAvailableRatherThanZero) {
    // Engine off, parking brake set: a correct gateway sends "not available" for engine speed.
    const auto d = decode_all();
    std::size_t eec1 = 0, parked = 0;
    for (const auto& m : d.messages) {
        for (const auto& s : j1939::decode_signals(m.pgn, m.data)) {
            if (s.def->spn == 190) {
                ++eec1;
                EXPECT_EQ(s.status, j1939::Status::NotAvailable);
            }
            if (s.def->spn == 70 && s.status == j1939::Status::Valid && s.raw == 1) ++parked;
        }
    }
    EXPECT_EQ(eec1, 972u);
    EXPECT_GT(parked, 180u);
}
