#include "libsesame3bt/ClientCore.h"
#include "ClientCoreImpl.h"

namespace libsesame3bt::core {

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
 * @param voltage
 * @return float battery remaining (0-100%)
 */
float
Status::voltage_to_pct(float voltage) {
	if (voltage >= batt_tbl[0].voltage) {
		return batt_tbl[0].pct;
	}
	if (voltage <= batt_tbl[std::size(batt_tbl) - 1].voltage) {
		return batt_tbl[std::size(batt_tbl) - 1].pct;
	}
	for (auto i = 1; i < std::size(batt_tbl); i++) {
		if (voltage >= batt_tbl[i].voltage) {
			return (voltage - batt_tbl[i].voltage) / (batt_tbl[i - 1].voltage - batt_tbl[i].voltage) *
			           (batt_tbl[i - 1].pct - batt_tbl[i].pct) +
			       batt_tbl[i].pct;
		}
	}
	return 0.0f;  // Never reach
}

/**
 * @brief return this model has setting
 * If this function returns false, get_setting() returns nullptr.
 *
 * @return true
 * @return false
 */
bool
libsesame3bt::core::SesameClientCore::has_setting() const {
	return impl->has_setting();
}

}  // namespace libsesame3bt::core
