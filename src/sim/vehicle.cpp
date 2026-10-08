#include "vnsl/sim/vehicle.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <numbers>

namespace vnsl::sim {
namespace {

// A typical 12-speed automated manual gearbox (ratios from public truck brochures, rounded).
constexpr std::array<double, 12> kRatios{14.94, 11.73, 9.04, 7.09, 5.54, 4.35, 3.44, 2.70, 2.08, 1.63, 1.27, 1.00};
constexpr double kGravity = 9.81;
constexpr double kRollingCoeff = 0.006;
constexpr double kAirDensity = 1.2;
constexpr double kDragArea = 6.0;   // Cd x frontal area, m^2
constexpr double kDriveEfficiency = 0.95;
constexpr double kShiftTimeS = 0.5;
constexpr double kUpshiftRpm = 1500;
constexpr double kDownshiftRpm = 1000;
constexpr double kTankLitres = 400;
constexpr double kBsfcGPerKWh = 200;  // brake-specific fuel consumption
constexpr double kDieselGPerL = 835;
constexpr double kIdleFuelLph = 1.2;

double rpm_from_mps(double v, double radius) { return v / (2.0 * std::numbers::pi * radius) * 60.0; }

}  // namespace

VehicleModel::VehicleModel(std::uint64_t seed) : rng_(seed) {
    std::uniform_real_distribution<double> u(0.0, 1.0);
    s_.distance_km = 120'000 + 80'000 * u(rng_);
    s_.engine_hours = 3'000 + 2'000 * u(rng_);
    s_.total_fuel_l = s_.engine_hours * 18.0;
    s_.fuel_level_pct = 40 + 50 * u(rng_);
    s_.ambient_c = -5 + 25 * u(rng_);
    s_.coolant_c = 70;
    s_.oil_temp_c = 72;
    s_.battery_v = 27.8;
    s_.engine_rpm = kIdleRpm;
}

double VehicleModel::ratio(int gear) {
    return gear >= 1 && gear <= 12 ? kRatios[static_cast<std::size_t>(gear - 1)] : 0.0;
}

void VehicleModel::drive_cycle(double t_cycle, double& target_kmh) {
    // 0-8 s parked (brake released at 6 s), 8-70 s pull away, 70-150 s cruise,
    // 150-175 s brake to a stop, 175-200 s parked (brake set at 180 s).
    s_.parking_brake = t_cycle < 6.0 || t_cycle >= 180.0;
    s_.cruise_active = t_cycle >= 70.0 && t_cycle < 150.0;
    s_.cruise_set_kmh = s_.cruise_active ? cycle_target_kmh_ : 0.0;
    if (t_cycle < 8.0 || t_cycle >= 175.0) {
        target_kmh = 0;
    } else if (t_cycle < 150.0) {
        target_kmh = cycle_target_kmh_;
    } else {
        target_kmh = -1;  // brake
    }
}

void VehicleModel::step(double dt) {
    s_.t_s += dt;
    const int cycle = static_cast<int>(s_.t_s / kCyclePeriodS);
    if (cycle != cycle_index_) {
        cycle_index_ = cycle;
        std::uniform_real_distribution<double> target(60.0, 85.0);
        cycle_target_kmh_ = std::round(target(rng_));
    }
    double target_kmh = 0;
    drive_cycle(std::fmod(s_.t_s, kCyclePeriodS), target_kmh);

    const double v = s_.speed_mps;
    const double resist = kRollingCoeff * kMassKg * kGravity * (v > 0.01 ? 1.0 : 0.0) + 0.5 * kAirDensity * kDragArea * v * v;

    // Longitudinal control: chase the target speed, limited by engine power and grip.
    double a_cmd = 0;
    s_.brake_pedal_pct = 0;
    if (target_kmh < 0) {
        a_cmd = v > 0.05 ? -1.0 : 0.0;
        s_.brake_pedal_pct = v > 0.05 ? 30.0 : 0.0;
    } else if (!s_.parking_brake) {
        a_cmd = std::clamp(0.5 * (target_kmh / 3.6 - v), -0.8, 0.6);
    }
    if (target_kmh == 0 && v < 0.3) {
        a_cmd = v > 0 ? -1.0 : 0.0;
        s_.brake_pedal_pct = v > 0 ? 20.0 : 0.0;
    }

    // Gear selection and shifting.
    if (shift_timer_s_ > 0) {
        shift_timer_s_ -= dt;
        if (shift_timer_s_ <= 0) s_.gear = shift_to_;
    } else if (v < 0.05 && a_cmd <= 0) {
        s_.gear = s_.parking_brake ? 0 : 1;
    } else {
        if (s_.gear == 0) s_.gear = 1;
        const double rpm = rpm_from_mps(v, kTyreRadiusM) * kFinalDrive * ratio(s_.gear);
        if (rpm > kUpshiftRpm && s_.gear < 12 && a_cmd > 0) {
            shift_to_ = s_.gear + 1;
            shift_timer_s_ = kShiftTimeS;
        } else if (rpm < kDownshiftRpm && s_.gear > 1 && v > 1.0) {
            shift_to_ = s_.gear - 1;
            shift_timer_s_ = kShiftTimeS;
        }
    }
    s_.shift_in_progress = shift_timer_s_ > 0;

    // Traction: no drive torque during a shift; power-limited otherwise.
    double drive_force = 0;
    if (a_cmd > 0 && !s_.shift_in_progress && s_.gear > 0) {
        const double wanted = kMassKg * a_cmd + resist;
        const double power_limit = kMaxPowerW * kDriveEfficiency / std::max(v, 1.0);
        const double torque_limit = kMaxTorqueNm * ratio(s_.gear) * kFinalDrive * kDriveEfficiency / kTyreRadiusM;
        drive_force = std::min({wanted, power_limit, torque_limit});
    } else if (a_cmd >= 0 && v > 0.05 && !s_.shift_in_progress && s_.gear > 0) {
        drive_force = std::min(resist, kMaxPowerW * kDriveEfficiency / std::max(v, 1.0));  // hold speed
    }
    const double brake_force = a_cmd < 0 ? std::max(0.0, -a_cmd * kMassKg - resist) : 0.0;
    const double accel = (drive_force - resist - brake_force) / kMassKg;
    s_.speed_mps = std::max(0.0, v + accel * dt);
    s_.accel_mps2 = accel;
    s_.distance_km += s_.speed_mps * dt / 1000.0;
    s_.trip_km += s_.speed_mps * dt / 1000.0;

    // Shaft speeds. Output shaft follows the wheels; the engine follows the input shaft when the
    // clutch is closed, otherwise it idles (or holds 800 rpm while the clutch slips at launch).
    s_.gear_ratio = ratio(s_.gear);
    s_.output_shaft_rpm = rpm_from_mps(s_.speed_mps, kTyreRadiusM) * kFinalDrive;
    s_.input_shaft_rpm = s_.output_shaft_rpm * s_.gear_ratio;
    const bool launching = s_.gear == 1 && s_.input_shaft_rpm < 800 && drive_force > 0;
    s_.clutch_engaged = s_.gear > 0 && !s_.shift_in_progress && !launching && s_.input_shaft_rpm >= kIdleRpm;
    if (s_.clutch_engaged) {
        s_.engine_rpm = s_.input_shaft_rpm;
        s_.clutch_slip_pct = 0;
    } else {
        s_.engine_rpm = launching ? 800.0 : kIdleRpm;
        s_.clutch_slip_pct = launching ? 100.0 * (1.0 - s_.input_shaft_rpm / 800.0) : 0.0;
    }

    // Torque, load and fuel.
    const double omega = s_.engine_rpm * 2.0 * std::numbers::pi / 60.0;
    const double engine_torque =
        s_.gear_ratio > 0 ? drive_force * kTyreRadiusM / (s_.gear_ratio * kFinalDrive * kDriveEfficiency) : 0.0;
    s_.torque_pct = std::clamp(100.0 * engine_torque / kMaxTorqueNm, 0.0, 100.0);
    s_.demand_pct = s_.torque_pct;
    s_.accel_pedal_pct = s_.cruise_active ? 0.0 : std::clamp(s_.torque_pct * 1.1, 0.0, 100.0);
    s_.load_pct = s_.torque_pct;
    const double power_kw = engine_torque * omega / 1000.0;
    s_.fuel_rate_lph = kIdleFuelLph + std::max(0.0, power_kw) * kBsfcGPerKWh / kDieselGPerL;
    const double litres = s_.fuel_rate_lph * dt / 3600.0;
    s_.total_fuel_l += litres;
    s_.fuel_level_pct = std::max(0.0, s_.fuel_level_pct - 100.0 * litres / kTankLitres);
    s_.engine_hours += dt / 3600.0;

    // Temperatures warm towards operating values; the electrical system charges.
    s_.coolant_c += (88.0 - s_.coolant_c) * dt / 300.0;
    s_.oil_temp_c += (95.0 - s_.oil_temp_c) * dt / 400.0;
    s_.battery_v = 27.8 + 0.05 * noise_(rng_);

    // Sensors: both count the same wheel rotation. The tachograph is calibrated to the tyre's
    // real radius; the ABS unit converts with a nominal radius 0.3 % larger than the worn tyre's,
    // so it reads 0.3 % high. Each has its own noise.
    const double true_kmh = s_.speed_mps * 3.6;
    s_.tacho_speed_kmh = std::max(0.0, true_kmh + (true_kmh > 0 ? 0.02 * noise_(rng_) : 0.0));
    s_.wheel_speed_kmh =
        std::max(0.0, true_kmh * kAbsAssumedRadiusM / kTyreRadiusM + (true_kmh > 0 ? 0.05 * noise_(rng_) : 0.0));
    s_.brake_switch = s_.brake_pedal_pct > 0;
}

}  // namespace vnsl::sim
