#include "libsesame3bt/ClientCore.h"
#include "ClientCoreImpl.h"

namespace libsesame3bt::core {

using model_t = Sesame::model_t;

SesameClientCore::SesameClientCore(SesameBLEBackend& backend) : impl(std::make_unique<SesameClientCoreImpl>(backend, *this)) {}

SesameClientCore::~SesameClientCore() {}

/**
 * @brief Initialize
 *
 * @param model SESAME model
 * @return true
 * @return false
 */
bool
SesameClientCore::begin(Sesame::model_t model) {
	return impl->begin(model);
}

/**
 * @brief Set SESAME keys
 *
 * @param public_key 64 bytes public key on SESAME OS2 device.
 * On OS3 devices, not used.
 * @param secret_key 16 bytes secret key.
 * @return true
 * @return false
 */
bool
SesameClientCore::set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
                           const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key) {
	return impl->set_keys(public_key, secret_key);
}

/**
 * @brief Set SESAME keys
 *
 * @param pk_str Hexstring public key on SESAME OS2 device.
 * On OS3 device nullptr may be used.
 * @param secret_str Hexstring private key.
 * @return true
 * @return false
 */
bool
SesameClientCore::set_keys(std::string_view pk_str, std::string_view secret_str) {
	return impl->set_keys(pk_str, secret_str);
}

/**
 * @brief Handle received notification data.
 *
 * @param data
 * @param size
 */
void
SesameClientCore::on_received(const std::byte* data, size_t size) {
	impl->on_received(data, size);
}

/**
 * @brief Process after disconnected.
 *
 */
void
SesameClientCore::on_disconnected() {
	impl->on_disconnected();
}

/**
 * @brief Unlock SESAME.
 *
 * @param tag TAG value for history entry. Ignoreed on Bot / Bot 2.
 * @return true
 * @return false
 */
bool
SesameClientCore::unlock(std::string_view tag) {
	return impl->unlock(tag);
}

/**
 * @brief Unlock SESAME.
 *
 * @param type Type of history tag.
 * @param uuid UUID value for history entry.
 * @return true
 * @return false
 */
bool
SesameClientCore::unlock(history_tag_type_t type, const std::array<std::byte, HISTORY_TAG_UUID_SIZE>& uuid) {
	return impl->unlock(type, uuid);
}

/**
 * @brief Lock SESAME.
 *
 * @param tag TAG value for history entry. Ignored on Bot / Bot 2.
 * @return true
 * @return false
 */
bool
SesameClientCore::lock(std::string_view tag) {
	return impl->lock(tag);
}

/**
 * @brief Lock SESAME.
 *
 * @param type Type of history tag.
 * @param uuid UUID value for history entry.
 * @return true
 * @return false
 */
bool
SesameClientCore::lock(history_tag_type_t type, const std::array<std::byte, HISTORY_TAG_UUID_SIZE>& uuid) {
	return impl->lock(type, uuid);
}

/**
 * @brief Click SESAME (for SESAME Bot / Bot 2).
 *
 * @param script_no script number. For Bot, specify zero(no meaning). For Bot 2 specify script number to run (0 to 9), if no value run currently selected script.
 * @return true
 * @return false
 */
bool
SesameClientCore::click(const std::optional<uint8_t> script_no) {
	return impl->click(script_no);
}

/**
 * @brief Click SESAME (for SESAME Bot).
 *
 * @param script_no script number. For Bot, specify zero(no meaning). For Bot 2 specify script number to run (0 to 9), if no value run currently selected script.
 * @return true
 * @return false
 */
bool
SesameClientCore::click(std::string_view tag) {
	return impl->click(tag);
}

/**
 * @brief Request history tag.
 *
 * @return true
 * @return false
 */
bool
SesameClientCore::request_history() {
	return impl->request_history();
}

/**
 * @brief Test if SESAME connection and authentication finished.
 *
 * @return true
 * @return false
 */
bool
SesameClientCore::is_session_active() const {
	return impl->is_session_active();
}

/**
 * @brief Test if keys are set.
 *
 * @return true
 * @return false
 */
bool
SesameClientCore::is_key_set() const {
	return impl->is_key_set();
}

/**
 * @brief Set callback for SESAME status changed.
 *
 * @param callback
 */
void
SesameClientCore::set_status_callback(status_callback_t callback) {
	impl->set_status_callback(callback);
}

/**
 * @brief Set callback for this library state changed.
 *
 * @param callback
 */
void
SesameClientCore::set_state_callback(state_callback_t callback) {
	impl->set_state_callback(callback);
}

/**
 * @brief Set callback for SESAME history tag received.
 *
 * @param callback
 */
void
SesameClientCore::set_history_callback(history_callback_t callback) {
	impl->set_history_callback(callback);
}

/**
 * @brief Set callback for notify registered Sesame devices (from Touch, OpenSensor, Remote)
 *
 * @param callback
 */
void
SesameClientCore::set_registered_devices_callback(registered_devices_callback_t callback) {
	impl->set_registered_devices_callback(callback);
}

/**
 * @brief SESAME model (initialized with begin()).
 *
 * @return Sesame::model_t
 */
Sesame::model_t
SesameClientCore::get_model() const {
	return impl->get_model();
}

/**
 * @brief Get library state.
 *
 * @return state_t
 */
state_t
SesameClientCore::get_state() const {
	return impl->get_state();
}

/**
 * @brief Get SESAME setting.
 * Settings are notified from SESAME only once when connected.
 * @note This method is valid when state is `state_t::active`
 *
 * @return const std::variant<nullptr_t, LockSetting, BotSetting>&
 */
const std::variant<std::nullptr_t, LockSetting, BotSetting>&
SesameClientCore::get_setting() const {
	return impl->get_setting();
}

/**
 * @brief Request SESAME to send status
 *
 * @note Not all models support this request (SESAME 5 / Bot 2 seems not respond)
 */
void
SesameClientCore::request_status() {
	return impl->request_status();
}

/**
 * @brief Convert voltage to estimated battery remaining
 *
 * @param voltage voltage
 * @param model Sesame model (optional). If not specified, sesame_5 is assumed.
 * @return float battery remaining percentage (0-100)
 */
float
Status::voltage_to_pct(float voltage, std::optional<Sesame::model_t> model) {
	return model.has_value() ? scaled_voltage_to_pct(scaled_voltage(voltage, *model), *model)
	                         : scaled_voltage_to_pct(scaled_voltage(voltage, model_t::sesame_5), model_t::sesame_5);
}

/**
 * @brief return this model has setting
 * If this function returns false, get_setting() returns nullptr.
 *
 * @return true
 * @return false
 */
bool
SesameClientCore::has_setting() const {
	return impl->has_setting();
}

/**
 * @brief number of series batterys
 *
 * @param model
 * @return uint8_t
 */
uint8_t
Status::battery_s(model_t model) {
	switch (model) {
		case model_t::sesame_bot:
		case model_t::sesame_bike:
		case model_t::sesame_bot_2:
		case model_t::sesame_bike_2:
		case model_t::open_sensor_1:
		case model_t::remote:
		case model_t::remote_nano:
			return 1;
		default:
			return 2;
	}
}

/**
 * @brief Convert raw status value to voltage
 *
 * @param status_value
 * @param model
 * @return float
 */
float
Status::status_value_to_voltage(uint16_t status_value, Sesame::model_t model) {
	auto os = Sesame::get_os_ver(model);
	switch (os) {
		case Sesame::os_ver_t::os2:
			return status_value * 3.6f * battery_s(model) / 1023;
		case Sesame::os_ver_t::os3:
			return status_value * battery_s(model) / 1000.0f;
		default:
			return 0.0f;
	}
}

/**
 * @brief Return 7.2V scaled voltage for OS3 devices
 *
 * @param status_value
 * @return float
 */
float
Status::status_value_to_scaled_voltage_os3(uint16_t status_value) {
	return status_value * 2.0f / 1000;
}

/**
 * @brief Scale voltage to 7.2V scale
 *
 * @param voltage
 * @param model
 * @return float
 */
float
Status::scaled_voltage(float voltage, Sesame::model_t model) {
	return voltage * 2.0f / battery_s(model);
}

/**
 * @brief Calculate battery percentage from scaled voltage
 * @note Currently, only OpenSensor uses a different table from the other models.
 *
 * @param voltage 7.2V scaled voltage
 * @param model
 * @return float battery remaining percentage (0-100)
 */
float
Status::scaled_voltage_to_pct(float voltage, Sesame::model_t model) {
	const BatteryTable* table = nullptr;
	size_t table_size = 0;
	if (model == model_t::open_sensor_1) {
		table = batt_tbl_open_sensor;
		table_size = std::size(batt_tbl_open_sensor);
	} else {
		table = batt_tbl;
		table_size = std::size(batt_tbl);
	}
	if (!table) {
		return 0.0f;
	}
	if (voltage >= table[0].voltage) {
		return table[0].pct;
	}
	if (voltage <= table[table_size - 1].voltage) {
		return table[table_size - 1].pct;
	}
	for (size_t i = 1; i < table_size; i++) {
		if (voltage >= table[i].voltage) {
			return (voltage - table[i].voltage) / (table[i - 1].voltage - table[i].voltage) * (table[i - 1].pct - table[i].pct) +
			       table[i].pct;
		}
	}
	return 0.0f;
}

}  // namespace libsesame3bt::core
