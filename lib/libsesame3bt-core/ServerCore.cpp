#include "libsesame3bt/ServerCore.h"
#include "ServerCoreImpl.h"
#include "debug.h"

namespace libsesame3bt::core {

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

std::tuple<std::string, std::string>
SesameServerCore::create_advertisement_data_os3() {
	return impl->create_advertisement_data_os3();
}

size_t
SesameServerCore::get_session_count() const {
	return impl->get_session_count();
}

bool
SesameServerCore::is_registered() {
	return impl->is_registered();
}
bool
SesameServerCore::generate_keypair() {
	return impl->generate_keypair();
}

bool
SesameServerCore::export_keypair(std::array<std::byte, 64>& pubkey, std::array<std::byte, 32>& privkey) {
	return impl->export_keypair(pubkey, privkey);
}

bool
SesameServerCore::set_registered(const std::array<std::byte, Sesame::SECRET_SIZE>& secret) {
	return impl->set_registered(secret);
}

bool
SesameServerCore::load_key(const std::array<std::byte, 32>& privkey) {
	return impl->load_key(privkey);
}

}  // namespace libsesame3bt::core
