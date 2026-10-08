#include "vnsl/sim/truck.hpp"

#include <algorithm>
#include <cmath>
#include <functional>
#include <optional>
#include <string>
#include <utility>

#include "vnsl/can/frame.hpp"
#include "vnsl/j1939/id.hpp"
#include "vnsl/j1939/signals.hpp"

namespace vnsl::sim {
namespace {

using Payload = std::vector<std::uint8_t>;
using Builder = std::function<Payload(const VehicleState&, double t_s)>;

/// NAME from its fields (J1939-81 layout). Values used here are illustrative.
std::uint64_t make_name(std::uint32_t identity, std::uint8_t function, std::uint8_t vehicle_system, bool arbitrary) {
    constexpr std::uint64_t kManufacturer = 0x7FE;  // illustrative, not a registered code
    constexpr std::uint64_t kIndustryOnHighway = 1;
    return (static_cast<std::uint64_t>(arbitrary) << 63) | (kIndustryOnHighway << 60) |
           (static_cast<std::uint64_t>(vehicle_system & 0x7F) << 49) | (static_cast<std::uint64_t>(function) << 40) |
           (kManufacturer << 21) | (identity & 0x1FFFFF);
}

Payload enc(std::uint32_t pgn, std::initializer_list<j1939::SignalInput> in) {
    const auto a = j1939::encode_signals(pgn, std::span<const j1939::SignalInput>(in.begin(), in.size()));
    return {a.begin(), a.end()};
}

double b(bool v) { return v ? 1.0 : 0.0; }

/// Steps the vehicle model every 10 ms. Not on the bus.
class ModelNode : public Node {
public:
    explicit ModelNode(VehicleModel& m) : model_(m) {}
    void start(Simulator& sim) override { sim.schedule(*this, kStepUs, 0); }
    void on_timer(Simulator& sim, int /*timer_id*/) override {
        model_.step(static_cast<double>(kStepUs) / 1e6);
        sim.schedule(*this, sim.now() + kStepUs, 0);
    }
    static constexpr std::uint64_t kStepUs = 10'000;

private:
    VehicleModel& model_;
};

/// An ECU that sends a fixed set of parameter groups on fixed periods, and answers requests
/// for any of them (plus extra on-request-only groups).
class PeriodicEcu : public J1939Node {
public:
    struct Periodic {
        std::uint32_t pgn;
        std::uint8_t priority;
        std::uint64_t period_us;
        Builder build;
    };

    PeriodicEcu(std::string label, std::uint64_t name, std::uint8_t address, const VehicleModel& model,
                std::vector<Periodic> periodic, std::vector<std::pair<std::uint32_t, Builder>> on_request_only = {})
        : J1939Node(std::move(label), name, address, false),
          model_(model),
          periodic_(std::move(periodic)),
          on_request_only_(std::move(on_request_only)) {}

protected:
    void on_claimed(Simulator& sim) override {
        // Spread first transmissions by 1 ms steps, as real ECUs start out of phase.
        for (std::size_t i = 0; i < periodic_.size(); ++i)
            schedule_app(sim, sim.now() + 1000 * (i + 1) + 137ULL * address(), static_cast<int>(i));
    }
    void on_app_timer(Simulator& sim, int id) override {
        const auto& p = periodic_[static_cast<std::size_t>(id)];
        const auto payload = p.build(model_.state(), static_cast<double>(sim.now()) / 1e6);
        send(sim, p.priority, p.pgn, j1939::kGlobalAddress, payload);
        schedule_app(sim, sim.now() + p.period_us, id);
    }
    std::optional<Payload> on_request(Simulator& sim, std::uint32_t pgn, std::uint8_t /*requester*/) override {
        const double t = static_cast<double>(sim.now()) / 1e6;
        for (const auto& p : periodic_)
            if (p.pgn == pgn) return p.build(model_.state(), t);
        for (const auto& [g, build] : on_request_only_)
            if (g == pgn) return build(model_.state(), t);
        return std::nullopt;
    }

private:
    const VehicleModel& model_;
    std::vector<Periodic> periodic_;
    std::vector<std::pair<std::uint32_t, Builder>> on_request_only_;
};

/// A service tool that runs a short script of requests after it has its address.
class ServiceTool : public J1939Node {
public:
    struct Step {
        double after_claim_s;
        std::uint32_t pgn;
        std::uint8_t da;
        double repeat_s;  ///< 0 = once
    };
    ServiceTool(std::string label, std::uint64_t name, std::uint8_t preferred, std::vector<Step> script)
        : J1939Node(std::move(label), name, preferred, true), script_(std::move(script)) {}

protected:
    void on_claimed(Simulator& sim) override {
        for (std::size_t i = 0; i < script_.size(); ++i)
            schedule_app(sim, sim.now() + static_cast<std::uint64_t>(script_[i].after_claim_s * 1e6), static_cast<int>(i));
    }
    void on_app_timer(Simulator& sim, int id) override {
        const auto& st = script_[static_cast<std::size_t>(id)];
        const Payload req{static_cast<std::uint8_t>(st.pgn & 0xFF), static_cast<std::uint8_t>((st.pgn >> 8) & 0xFF),
                          static_cast<std::uint8_t>((st.pgn >> 16) & 0xFF)};
        send(sim, 6, j1939::kPgnRequest, st.da, req);
        if (st.repeat_s > 0) schedule_app(sim, sim.now() + static_cast<std::uint64_t>(st.repeat_s * 1e6), id);
    }

private:
    std::vector<Step> script_;
};

}  // namespace

struct Truck::Impl {
    VehicleModel model;
    std::unique_ptr<ModelNode> model_node;
    std::vector<std::unique_ptr<J1939Node>> nodes;
    explicit Impl(std::uint64_t seed) : model(seed) {}
};

Truck::Truck(Simulator& sim, const TruckConfig& cfg) : impl_(std::make_unique<Impl>(cfg.seed)) {
    auto& m = impl_->model;
    impl_->model_node = std::make_unique<ModelNode>(m);
    sim.add(*impl_->model_node);
    const double fault_at = cfg.fault_at_s;
    const std::uint64_t epoch = cfg.start_epoch_s;

    // ---- Engine (0x00) ----
    std::vector<PeriodicEcu::Periodic> engine{
        {61444, 3, 20'000,
         [](const VehicleState& s, double) {
             return enc(61444, {{899, s.torque_pct > 0 ? 1.0 : 0.0}, {512, s.demand_pct}, {513, s.torque_pct},
                                {190, s.engine_rpm}, {1483, 0}, {1675, 0}, {2432, s.demand_pct}});
         }},
        {61443, 3, 50'000,
         [](const VehicleState& s, double) {
             return enc(61443, {{558, b(s.accel_pedal_pct < 1)}, {559, 0}, {91, s.accel_pedal_pct}, {92, s.load_pct}});
         }},
        {65266, 6, 100'000,
         [](const VehicleState& s, double) {
             const double kmh = s.wheel_speed_kmh;
             return enc(65266, {{183, s.fuel_rate_lph}, {184, kmh > 0.5 ? kmh / s.fuel_rate_lph : 0.0}, {185, 2.9}});
         }},
        {65263, 6, 500'000,
         [](const VehicleState& s, double) {
             return enc(65263, {{94, 520}, {98, 85}, {100, std::min(600.0, 150.0 + 0.2 * s.engine_rpm)}, {109, 120}, {111, 95}});
         }},
        {65262, 6, 1'000'000,
         [](const VehicleState& s, double) {
             return enc(65262, {{110, s.coolant_c}, {174, s.ambient_c + 15}, {175, s.oil_temp_c}});
         }},
        {65269, 6, 1'000'000,
         [](const VehicleState& s, double) {
             return enc(65269, {{108, 101}, {170, 21}, {171, s.ambient_c}, {172, s.ambient_c + 5}});
         }},
        {65253, 6, 1'000'000,
         [](const VehicleState& s, double) {
             return enc(65253, {{247, s.engine_hours}, {249, s.engine_hours * 1400 * 60}});
         }},
        {65257, 6, 1'000'000,
         [](const VehicleState& s, double) { return enc(65257, {{182, s.total_fuel_l}, {250, s.total_fuel_l}}); }},
        {64777, 6, 1'000'000,
         [](const VehicleState& s, double) { return enc(64777, {{5053, s.total_fuel_l}, {5054, s.total_fuel_l}}); }},
        {65271, 6, 1'000'000,
         [](const VehicleState& s, double) {
             return enc(65271, {{167, 28.0}, {168, s.battery_v}, {158, s.battery_v - 0.1}});
         }},
        {j1939::kPgnDm1, 6, 1'000'000,
         [fault_at](const VehicleState&, double t) {
             j1939::Dm1 dm;
             dm.malfunction_lamp = 0;
             dm.red_stop_lamp = 0;
             dm.protect_lamp = 0;
             dm.amber_warning_lamp = t >= fault_at ? 1 : 0;
             if (t >= fault_at) dm.dtcs = {{3226, 2, 1, false}, {4364, 18, 1, false}};  // illustrative codes
             return j1939::encode_dm1(dm);
         }},
    };
    const std::vector<std::pair<std::uint32_t, Builder>> engine_on_request{
        {65260, [](const VehicleState&, double) {
             const std::string vin = "1VNSL00SIM0000001*";  // obviously simulated, '*' ends the field
             return Payload(vin.begin(), vin.end());
         }}};
    impl_->nodes.push_back(std::make_unique<PeriodicEcu>("engine", make_name(1, 0, 0, false), 0x00, m, std::move(engine),
                                                         engine_on_request));

    // ---- Transmission (0x03) ----
    impl_->nodes.push_back(std::make_unique<PeriodicEcu>(
        "transmission", make_name(2, 3, 0, false), 0x03, m,
        std::vector<PeriodicEcu::Periodic>{
            {61442, 3, 10'000,
             [](const VehicleState& s, double) {
                 return enc(61442, {{560, b(s.clutch_engaged)}, {573, 0}, {574, b(s.shift_in_progress)},
                                    {191, s.output_shaft_rpm}, {522, s.clutch_slip_pct}, {161, s.input_shaft_rpm},
                                    {1482, 3}});
             }},
            {61445, 6, 100'000,
             [](const VehicleState& s, double) {
                 const double gear = s.shift_in_progress ? 0 : s.gear;
                 return enc(61445, {{524, static_cast<double>(s.gear)}, {526, s.gear_ratio}, {523, gear}});
             }},
        }));

    // ---- Brakes (0x0B) ----
    impl_->nodes.push_back(std::make_unique<PeriodicEcu>(
        "brakes", make_name(3, 9, 0, false), 0x0B, m,
        std::vector<PeriodicEcu::Periodic>{
            {61441, 6, 100'000,
             [](const VehicleState& s, double) {
                 return enc(61441, {{561, 0}, {562, 0}, {563, 0}, {1121, b(s.brake_switch)}, {521, s.brake_pedal_pct}});
             }},
        }));

    // ---- Instrument cluster (0x17) ----
    impl_->nodes.push_back(std::make_unique<PeriodicEcu>(
        "cluster", make_name(4, 0x17, 0, false), 0x17, m,
        std::vector<PeriodicEcu::Periodic>{
            {65265, 6, 100'000,
             [](const VehicleState& s, double) {
                 return enc(65265, {{69, 0}, {70, b(s.parking_brake)}, {84, s.wheel_speed_kmh}, {595, b(s.cruise_active)},
                                    {596, 1}, {597, b(s.brake_switch)}, {598, 0}, {86, s.cruise_set_kmh}, {976, 0}});
             }},
            {65217, 6, 1'000'000,
             [](const VehicleState& s, double) { return enc(65217, {{917, s.distance_km}, {918, s.trip_km}}); }},
            {65276, 6, 1'000'000,
             [](const VehicleState& s, double) { return enc(65276, {{80, 70}, {96, s.fuel_level_pct}}); }},
        }));

    // ---- Tachograph (0xEE) ----
    impl_->nodes.push_back(std::make_unique<PeriodicEcu>(
        "tachograph", make_name(5, 0x19, 0, false), 0xEE, m,
        std::vector<PeriodicEcu::Periodic>{
            {65132, 3, 50'000,
             [](const VehicleState& s, double) {
                 const bool moving = s.speed_mps > 0.1;
                 return enc(65132, {{1612, moving ? 3.0 : 2.0}, {1613, 0}, {1611, b(moving)}, {1617, 0}, {1615, 1},
                                    {1614, b(s.tacho_speed_kmh > 90)}, {1618, 0}, {1616, 0}, {1622, 0}, {1621, 0},
                                    {1620, 0}, {1619, 0}, {1623, s.output_shaft_rpm}, {1624, s.tacho_speed_kmh}});
             }},
            {65254, 6, 1'000'000,
             [epoch](const VehicleState&, double t) {
                 // Calendar time from the configured start, in UTC.
                 const double now = static_cast<double>(epoch) + t;
                 const auto secs = static_cast<std::int64_t>(std::floor(now));
                 const double frac = now - static_cast<double>(secs);
                 std::int64_t days = secs / 86400;
                 const std::int64_t sod = secs % 86400;
                 // civil_from_days (Howard Hinnant)
                 days += 719468;
                 const std::int64_t era = days / 146097;
                 const auto doe = static_cast<unsigned>(days - era * 146097);
                 const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
                 const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
                 const unsigned mp = (5 * doy + 2) / 153;
                 const unsigned d = doy - (153 * mp + 2) / 5 + 1;
                 const unsigned mo = mp < 10 ? mp + 3 : mp - 9;
                 const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400 + (mo <= 2 ? 1 : 0);
                 const std::int64_t minute = (sod / 60) % 60;
                 const std::int64_t hour = sod / 3600;
                 return enc(65254, {{959, std::floor((static_cast<double>(sod % 60) + frac) * 4) / 4},
                                    {960, static_cast<double>(minute)},
                                    {961, static_cast<double>(hour)},
                                    {963, static_cast<double>(mo)},
                                    {962, static_cast<double>(d)},
                                    {964, static_cast<double>(y)},
                                    {1601, 0},
                                    {1602, 0}});
             }},
        }));

    // ---- Service tool (0xF9) ----
    const std::uint32_t kVi = 65260;
    impl_->nodes.push_back(std::make_unique<ServiceTool>(
        "service-tool", make_name(6, 129, 0, true), 0xF9,
        std::vector<ServiceTool::Step>{
            {1.0, j1939::kPgnAddressClaimed, j1939::kGlobalAddress, 0},  // who is on the bus?
            {2.0, kVi, 0x00, 60.0},                                      // vehicle ID, point to point, every minute
            {3.0, 65253, j1939::kGlobalAddress, 0},                       // engine hours, from anyone
            {4.0, 65261, 0x03, 0},                                        // a group the transmission lacks: NACK
            {fault_at + 2.0, j1939::kPgnDm1, 0x00, 0},                    // trouble codes, point to point
        }));

    if (cfg.address_conflict) {
        // A second tool, plugged in at 10 s, wants 0xF9 too. Its NAME is higher (lower
        // priority), so the first tool defends 0xF9 and the newcomer moves to 0x80.
        auto tool2 = std::make_unique<ServiceTool>("service-tool-2", make_name(7, 129, 0, true), 0xF9,
                                                   std::vector<ServiceTool::Step>{{2.0, kVi, 0x00, 0}});
        tool2->set_start_delay(10'000'000);
        impl_->nodes.push_back(std::move(tool2));
    }
    for (auto& n : impl_->nodes) sim.add(*n);
}

Truck::~Truck() = default;

const VehicleModel& Truck::model() const { return impl_->model; }

std::vector<const J1939Node*> Truck::nodes() const {
    std::vector<const J1939Node*> out;
    for (const auto& n : impl_->nodes) out.push_back(n.get());
    return out;
}

}  // namespace vnsl::sim
