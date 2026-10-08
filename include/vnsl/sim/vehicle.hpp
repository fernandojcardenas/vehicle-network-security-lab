#pragma once

#include <cstdint>
#include <random>

namespace vnsl::sim {

/// Everything the simulated ECUs report, computed from one physical state.
struct VehicleState {
    double t_s = 0;
    // Motion
    double speed_mps = 0;        ///< true road speed
    double accel_mps2 = 0;
    double distance_km = 0;      ///< total vehicle distance (odometer)
    double trip_km = 0;
    // Driveline
    int gear = 0;                ///< 0 neutral, 1..12
    double gear_ratio = 0;       ///< 0 in neutral
    bool clutch_engaged = false;
    bool shift_in_progress = false;
    double engine_rpm = 600;
    double input_shaft_rpm = 0;
    double output_shaft_rpm = 0;
    double clutch_slip_pct = 0;
    // What the sensors report (each has its own error, as on a real truck)
    double wheel_speed_kmh = 0;  ///< from the ABS wheel sensors (assumed-radius error + noise)
    double tacho_speed_kmh = 0;  ///< from the tachograph's output-shaft sensor (calibrated)
    // Engine
    double torque_pct = 0;       ///< actual engine percent torque
    double demand_pct = 0;       ///< driver's demand percent torque
    double accel_pedal_pct = 0;
    double load_pct = 0;
    double fuel_rate_lph = 0;
    double total_fuel_l = 0;
    double engine_hours = 0;
    double coolant_c = 0;
    double oil_temp_c = 0;
    double fuel_level_pct = 0;
    double battery_v = 0;
    double ambient_c = 0;
    // Driver controls
    double brake_pedal_pct = 0;
    bool brake_switch = false;
    bool parking_brake = true;
    bool cruise_active = false;
    double cruise_set_kmh = 0;
};

/// A heavy truck on a repeating drive cycle: parked idle, pull away through twelve gears,
/// cruise, brake to a stop, park. Simple longitudinal physics (power-limited traction, rolling
/// and air resistance), a 12-speed automated gearbox with 0.5 s shifts, and sensors with
/// independent errors. Everything is driven by a seeded generator, so a run is reproducible.
///
/// It is a plausible model, not a validated one: the point is traffic whose values are
/// physically consistent with each other (engine speed, gear, shaft speeds, two speed sensors,
/// fuel, distance), which is what an intrusion detector can check.
class VehicleModel {
public:
    explicit VehicleModel(std::uint64_t seed);

    /// Advances the model by `dt_s` seconds (use small steps, e.g. 0.01 s).
    void step(double dt_s);

    [[nodiscard]] const VehicleState& state() const { return s_; }

    // Vehicle parameters (public so tests and docs can use the same numbers).
    static constexpr double kMassKg = 20'000;
    static constexpr double kTyreRadiusM = 0.510;         ///< real dynamic radius (the tachograph is calibrated to it)
    static constexpr double kAbsAssumedRadiusM = 0.5115;  ///< radius the ABS unit assumes: its speed reads 0.3 % high
    static constexpr double kFinalDrive = 2.85;
    static constexpr double kMaxTorqueNm = 2500;
    static constexpr double kMaxPowerW = 330'000;
    static constexpr double kIdleRpm = 600;
    static constexpr double kCyclePeriodS = 200;

private:
    void drive_cycle(double t_cycle, double& target_kmh);
    [[nodiscard]] static double ratio(int gear);

    VehicleState s_;
    std::mt19937_64 rng_;
    std::normal_distribution<double> noise_{0.0, 1.0};
    double cycle_target_kmh_ = 80;
    int cycle_index_ = -1;
    double shift_timer_s_ = 0;
    int shift_to_ = 0;
};

}  // namespace vnsl::sim
