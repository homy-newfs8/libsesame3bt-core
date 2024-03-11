#include "libsesame3bt/core.h"
#include "SesameClientCoreImpl.h"

namespace libsesame3bt::core {

SesameClientCore::SesameClientCore(SesameClientBackend* backend) : impl(std::make_unique<SesameClientCoreImpl>(backend)) {}

SesameClientCore::~SesameClientCore() {}

bool
SesameClientCore::begin(Sesame::model_t model) {
	return impl->begin(model);
}

bool
SesameClientCore::set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
                           const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key) {
	return impl->set_keys(public_key, secret_key);
}
bool
SesameClientCore::set_keys(const char* pk_str, const char* secret_str) {
	return impl->set_keys(pk_str, secret_str);
}
bool
SesameClientCore::on_connected() {
	return impl->on_connected();
}
void
SesameClientCore::on_received(const std::byte* data, size_t size) {
	impl->on_received(data, size);
}
void
SesameClientCore::on_disconnected() {
	impl->on_disconnected();
}
bool
SesameClientCore::unlock(const char* tag) {
	return impl->unlock(tag);
}
bool
SesameClientCore::lock(const char* tag) {
	return impl->lock(tag);
}
bool
SesameClientCore::click(const char* tag) {
	return impl->click(tag);
}
bool
SesameClientCore::request_history() {
	return impl->request_history();
}
bool
SesameClientCore::is_session_active() const {
	return impl->is_session_active();
}
void
SesameClientCore::set_status_callback(SesameClientCore::status_callback_t callback) {
	impl->set_status_callback(callback);
}
void
SesameClientCore::set_state_callback(SesameClientCore::state_callback_t callback) {
	impl->set_state_callback(callback);
}
void
SesameClientCore::set_history_callback(SesameClientCore::history_callback_t callback) {
	impl->set_history_callback(callback);
}
Sesame::model_t
SesameClientCore::get_model() const {
	return impl->get_model();
}
SesameClientCore::state_t
SesameClientCore::get_state() const {
	return impl->get_state();
}
const std::variant<LockSetting, BotSetting>&
SesameClientCore::get_setting() const {
	return impl->get_setting();
}

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

}  // namespace libsesame3bt::core
