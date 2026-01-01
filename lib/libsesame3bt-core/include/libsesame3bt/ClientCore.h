#pragma once
#include <array>
#include <atomic>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>
#include <variant>
#include "BLEBackend.h"
#include "Sesame.h"

namespace libsesame3bt::core {

/**
   * @brief Lock device setting
   *
   */
class LockSetting {
 public:
	LockSetting() {}
	LockSetting(const Sesame::mecha_setting_t& setting)
	    : _lock_position(setting.lock.lock_position), _unlock_position(setting.lock.unlock_position), _auto_lock_sec(-1) {}
	LockSetting(const Sesame::mecha_setting_5_t& setting)
	    : _lock_position(setting.lock_position), _unlock_position(setting.unlock_position), _auto_lock_sec(setting.auto_lock_sec) {}

	int16_t lock_position() const { return _lock_position; }
	int16_t unlock_position() const { return _unlock_position; }
	int16_t auto_lock_sec() const { return _auto_lock_sec; }

 private:
	int16_t _lock_position = 0;
	int16_t _unlock_position = 0;
	int16_t _auto_lock_sec = 0;
};

/**
   * @brief bot device setting
   *
   */
class BotSetting {
 public:
	BotSetting() : setting{} {}
	BotSetting(const Sesame::mecha_setting_t& setting) : setting(setting) {}
	/**
		 * @brief First rotation direction on @link libsesame3bt::SesameClient::click click @endlink operation
		 *
		 * @return 0: push, 1: pull
		 */
	uint8_t user_pref_dir() const { return setting.bot.user_pref_dir; }
	/**
		 * @brief Lock time
		 *
		 * @return Rotation time in 1/10 seconds unit
		 */
	uint8_t lock_sec() const { return setting.bot.lock_sec; }
	/**
		 * @brief Unlock time
		 *
		 * @return Rotation time in 1/10 seconds unit
		 */
	uint8_t unlock_sec() const { return setting.bot.unlock_sec; }
	/**
		 * @brief Lock time on @link libsesame3bt::SesameClient::click click @endlink operation
		 *
		 * @return Rotation time in 1/10 seconds unit
		 */
	uint8_t click_lock_sec() const { return setting.bot.click_lock_sec; }
	/**
		 * @brief Unlock time on @link libsesame3bt::SesameClient::click click @endlink operation
		 *
		 * @return Rotation time in 1/10 seconds unit
		 */
	uint8_t click_unlock_sec() const { return setting.bot.click_unlock_sec; }
	/**
		 * @brief Hold time on @link libsesame3bt::SesameClient::click click @endlink operation
		 *
		 * @return Rotation time in 1/10 seconds unit
		 */
	uint8_t click_hold_sec() const { return setting.bot.click_hold_sec; }
	uint8_t button_mode() const { return setting.bot.button_mode; }

 private:
	Sesame::mecha_setting_t setting;
};

struct BatteryTable {
	float voltage;
	float pct;
};

/**
   * @brief Device status
   *
   */
class Status {
 public:
	Status() {}
	Status(const Sesame::mecha_status_t::mecha_lock_status_t& status, Sesame::model_t model)
	    : _voltage(status_value_to_voltage(status.battery, model)),
	      _batt_pct(voltage_to_pct(_voltage, model)),
	      _target(status.target),
	      _position(status.position),
	      _ret_code(status.retcode),
	      _in_lock(status.in_lock),
	      _in_unlock(status.in_unlock),
	      _battery_critical(status.is_battery_critical),
	      _stopped(false),
	      _motor_status{} {}
	Status(const Sesame::mecha_status_t::mecha_bot_status_t& status, Sesame::model_t model)
	    : _voltage(status_value_to_voltage(status.battery, model)),
	      _batt_pct(voltage_to_pct(_voltage, model)),
	      _in_lock(status.in_lock),
	      _in_unlock(status.in_unlock),
	      _battery_critical(status.is_battery_critical),
	      _stopped(status.motor_status == Sesame::motor_status_t::idle || status.motor_status == Sesame::motor_status_t::holding),
	      _motor_status(status.motor_status) {}
	Status(const Sesame::mecha_bot_2_status_t& status, Sesame::model_t model)
	    : _voltage(status_value_to_voltage(status.battery, model)),
	      _batt_pct(voltage_to_pct(_voltage, model)),
	      _in_lock(status.in_lock),
	      _in_unlock(!status.in_lock),
	      _stopped(status.is_idle),
	      _motor_status{} {};
	Status(const Sesame::mecha_bike_2_status_t& status, Sesame::model_t model)
	    : _voltage(status_value_to_voltage(status.battery, model)),
	      _batt_pct(voltage_to_pct(_voltage, model)),
	      _in_lock(status.in_lock),
	      _in_unlock(!status.in_lock),
	      _stopped(status.is_stop),
	      _motor_status{} {}
	Status(const Sesame::mecha_status_5_t& status, Sesame::model_t model)
	    : _voltage(status_value_to_voltage(status.battery, model)),
	      _batt_pct(voltage_to_pct(_voltage, model)),
	      _target(status.target),
	      _position(status.position),
	      _in_lock(status.in_lock),
	      _in_unlock(!status.in_lock),
	      _battery_critical(status.is_battery_critical),
	      _stopped(status.is_stop),
	      _is_critical(status.is_critical),
	      _motor_status{},
	      _is_clutch_failed(status.is_clutch_failed) {}
	float voltage() const { return _voltage; }
	[[deprecated("use battery_critical() instead")]] bool voltage_critical() const { return _battery_critical; }
	bool battery_critical() const { return _battery_critical; }
	bool in_lock() const { return _in_lock; }
	bool in_unlock() const { return _in_unlock; }
	int16_t target() const { return _target; }
	int16_t position() const { return _position; }
	float battery_pct() const { return _batt_pct; }
	/// @note stopped is not meaningful for SESAME 3 / SESAME 4
	bool stopped() const { return _stopped; }
	bool is_critical() const { return _is_critical; }
	bool is_clutch_failed() const { return _is_clutch_failed; }
	/// @note motor_status is meaningful only for Bot (not Bot 2)
	Sesame::motor_status_t motor_status() const { return _motor_status; }
	uint8_t ret_code() const { return _ret_code; }

	bool operator==(const Status& that) const {
		if (&that == this) {
			return true;
		}
		return _model == that._model && _voltage == that._voltage && _position == that._position && _in_lock == that._in_lock &&
		       _in_unlock == that._in_unlock && _stopped == that._stopped && _motor_status == that._motor_status;
	}
	bool operator!=(const Status& that) const { return !(*this == that); }
	static float voltage_to_pct(float voltage, std::optional<Sesame::model_t> model = std::nullopt);
	static float status_value_to_voltage(uint16_t status_value, Sesame::model_t model);
	static float status_value_to_scaled_voltage_os3(uint16_t status_value);
	static float scaled_voltage_to_pct(float voltage, Sesame::model_t model);

 private:
	Sesame::model_t _model = Sesame::model_t::unknown;
	float _voltage = 0;
	float _batt_pct = 0;
	int16_t _target = 0;
	int16_t _position = 0;
	int8_t _ret_code = 0;
	bool _in_lock = false;
	bool _in_unlock = false;
	bool _battery_critical = false;
	bool _stopped = false;
	bool _is_critical = false;
	Sesame::motor_status_t _motor_status = Sesame::motor_status_t::idle;
	bool _is_clutch_failed = false;
	static uint8_t battery_s(Sesame::model_t model);
	static float scaled_voltage(float voltage, Sesame::model_t model);
	static inline const BatteryTable batt_tbl[] = {{5.85f, 100.0f}, {5.82f, 95.0f}, {5.79f, 90.0f}, {5.76f, 85.0f},
	                                               {5.73f, 80.0f},  {5.70f, 70.0f}, {5.65f, 60.0f}, {5.60f, 50.0f},
	                                               {5.55f, 40.0f},  {5.50f, 32.0f}, {5.40f, 21.0f}, {5.20f, 13.0f},
	                                               {5.10f, 10.0f},  {5.0f, 7.0f},   {4.8f, 3.0f},   {4.6f, 0.0f}};
	static inline const BatteryTable batt_tbl_open_sensor[] = {{5.820f, 100.0f}, {5.810f, 95.0f}, {5.755f, 90.0f}, {5.735f, 85.0f},
	                                                           {5.665f, 80.0f},  {5.620f, 70.0f}, {5.585f, 60.0f}, {5.556f, 50.0f},
	                                                           {5.550f, 40.0f},  {5.530f, 32.0f}, {5.450f, 21.0f}, {5.400f, 13.0f},
	                                                           {5.320f, 10.0f},  {5.280f, 7.0f},  {5.225f, 3.0f},  {5.150f, 0.0f}};
};

/**
   * @brief Operation history entry
   *
   */
struct History {
	Sesame::result_code_t result;
	Sesame::history_type_t type;
	union {
		std::optional<history_tag_type_t> trigger_type [[deprecated("use history_tag_type instead")]];
		std::optional<history_tag_type_t> history_tag_type;
	};
	int32_t record_id;
	time_t time;
	uint8_t tag_len;
	char tag[Sesame::MAX_HISTORY_TAG_SIZE + 1];
};

enum class state_t : uint8_t { idle, authenticating, active };

struct RegisteredDevice {
	uint8_t uuid[16];
	Sesame::os_ver_t os_ver;
};

class SesameClientCoreImpl;
class SesameClientCore;
using status_callback_t = std::function<void(SesameClientCore& client, Status status)>;
using state_callback_t = std::function<void(SesameClientCore& client, state_t state)>;
using history_callback_t = std::function<void(SesameClientCore& client, const History& history)>;
using registered_devices_callback_t = std::function<void(SesameClientCore& client, const std::vector<RegisteredDevice>& devices)>;

/**
 * @brief Sesame client
 *
 */
class SesameClientCore {
 public:
	SesameClientCore(SesameBLEBackend&);
	SesameClientCore(const SesameClientCore&) = delete;
	SesameClientCore& operator=(const SesameClientCore&) = delete;
	virtual ~SesameClientCore();
	bool begin(Sesame::model_t model);
	bool set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
	              const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key);
	bool set_keys(std::string_view pk_str, std::string_view secret_str);
	bool unlock(std::string_view tag);
	bool unlock(history_tag_type_t type, const std::array<std::byte, HISTORY_TAG_UUID_SIZE>& uuid);
	bool lock(std::string_view tag);
	bool lock(history_tag_type_t type, const std::array<std::byte, HISTORY_TAG_UUID_SIZE>& uuid);
	bool click(const std::optional<uint8_t> script_no = std::nullopt);
	bool click(std::string_view tag);
	bool request_history();
	bool is_session_active() const;
	bool is_key_set() const;
	void set_status_callback(status_callback_t callback);
	void set_state_callback(state_callback_t callback);
	void set_history_callback(history_callback_t callback);
	void set_registered_devices_callback(registered_devices_callback_t callback);
	Sesame::model_t get_model() const;
	state_t get_state() const;
	const std::variant<std::nullptr_t, LockSetting, BotSetting>& get_setting() const;
	bool has_setting() const;
	void request_status();

	void on_received(const std::byte*, size_t);
	void on_disconnected();

 private:
	std::unique_ptr<SesameClientCoreImpl> impl;
};

}  // namespace libsesame3bt::core
