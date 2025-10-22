#include "libsesame3bt/ServerCore.h"
#include "ServerCoreImpl.h"
#include "crypt.h"
#include "debug.h"

namespace libsesame3bt::core {

namespace {

constexpr std::array<std::byte, 5> CANDY = {std::byte{'c'}, std::byte{'a'}, std::byte{'n'}, std::byte{'d'}, std::byte{'y'}};

}

/// @brief Make BLE address from 128-bit UUID (SESAME 5 or later)
/// @param uuid (big-endian) 128-bit UUID
/// @return BLE address (6 bytes, big-endian, with the two most significant bits set to 1)
/// @note Return all-zeros on failure.
std::array<std::byte, 6>
SesameServerCore::uuid_to_ble_address(const std::byte (&uuid)[16]) {
	CmacAes128 cmac;
	cmac.set_key(uuid);
	cmac.update(CANDY);
	std::array<std::byte, 16> out;
	auto rc = cmac.finish(out);
	if (!rc) {
		DEBUG_PRINTF("Failed to create BLE address from UUID\n");
		return {};
	}
	return std::array<std::byte, 6>{out[5] | std::byte{0xC0}, out[4], out[3], out[2], out[1], out[0]};
}

SesameServerCore::SesameServerCore(ServerBLEBackend& backend, int max_sessions)
    : impl(std::make_unique<SesameServerCoreImpl>(backend, *this, max_sessions)) {}

SesameServerCore::~SesameServerCore() {}

bool
SesameServerCore::begin(libsesame3bt::Sesame::model_t model, const uint8_t (&uuid)[16]) {
	return impl->begin(model, uuid);
}

void
SesameServerCore::update() {
	impl->update();
}

bool
SesameServerCore::on_subscribed(uint16_t session_id) {
	return impl->on_subscribed(session_id);
}

bool
SesameServerCore::on_received(uint16_t session_id, const std::byte* data, size_t size) {
	return impl->on_received(session_id, data, size);
}

void
SesameServerCore::on_disconnected(uint16_t session_id) {
	impl->on_disconnected(session_id);
}

void
SesameServerCore::set_on_registration_callback(registration_callback_t callback) {
	impl->set_on_registration_callback(callback);
}

void
SesameServerCore::set_on_command_callback(command_callback_t callback) {
	impl->set_on_command_callback(callback);
}

void
SesameServerCore::set_mecha_setting(const Sesame::mecha_setting_5_t& setting) {
	impl->set_mecha_setting(setting);
}

void
SesameServerCore::set_mecha_status(const Sesame::mecha_status_5_t& status) {
	impl->set_mecha_status(status);
}

std::tuple<std::string, std::string>
SesameServerCore::create_advertisement_data_os3() const {
	return impl->create_advertisement_data_os3();
}

size_t
SesameServerCore::get_session_count() const {
	return impl->get_session_count();
}

bool
SesameServerCore::is_registered() const {
	return impl->is_registered();
}

bool
SesameServerCore::set_registered(const std::array<std::byte, Sesame::SECRET_SIZE>& secret) {
	return impl->set_registered(secret);
}

bool
libsesame3bt::core::SesameServerCore::send_notify(std::optional<uint16_t> session_id,
                                                  Sesame::op_code_t op_code,
                                                  Sesame::item_code_t item_code,
                                                  const std::byte* data,
                                                  size_t size) {
	return impl->send_notify(session_id, op_code, item_code, data, size);
}

bool
SesameServerCore::has_session(uint16_t session_id) const {
	return impl->has_session(session_id);
}

}  // namespace libsesame3bt::core
