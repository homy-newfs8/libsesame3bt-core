#include "libsesame3bt/ServerCore.h"
#include "SesameServerCoreImpl.h"
#include "debug.h"

namespace libsesame3bt::core {

SesameServerCore::SesameServerCore(SesameBLEBackend& backend) : impl(std::make_unique<SesameServerCoreImpl>(backend, *this)) {}

SesameServerCore::~SesameServerCore() {}

void
SesameServerCore::on_subscribed() {
	impl->on_subscribed();
}

void
SesameServerCore::on_received(const std::byte* data, size_t size) {
	impl->on_received(data, size);
}

void
SesameServerCore::on_disconnected() {
	impl->on_disconnected();
}

void
SesameServerCore::set_on_registration_callback(registration_callback_t callback) {
	impl->set_on_registration_callback(callback);
}

void
SesameServerCore::set_on_command_callback(command_callback_t callback) {
	impl->set_on_command_callback(callback);
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
