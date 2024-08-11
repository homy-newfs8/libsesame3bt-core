#pragma once
#include <cstddef>
#include "Sesame.h"
#include "crypt.h"
#include "crypt_ecc.h"
#include "libsesame3bt/BLEBackend.h"
#include "libsesame3bt/ServerCore.h"
#include "transport.h"

namespace libsesame3bt::core {

class SesameServerCoreImpl {
 public:
	SesameServerCoreImpl(SesameBLEBackend& backend, SesameServerCore& core);
	void begin_activation();
	bool generate_keypair();
	bool load_key(const std::array<std::byte, 32>& privkey);
	void on_received(const std::byte* data, size_t size);
	void on_disconnected();
	bool export_keypair(std::array<std::byte, 64>& pubkey, std::array<std::byte, 32>& privkey);
	void set_on_registration_callback(registration_callback_t callback) { on_registration_callback = callback; }
	bool set_registered(const std::array<std::byte, Sesame::SECRET_SIZE>& secret);
	bool is_registered() const { return registered; }

 private:
	SesameServerCore& core;
	SesameBLETransport transport;
	CryptHandler crypt{std::in_place_type<OS3IVHandler>};
	std::byte nonce[4];
	Ecc ecc;
	std::array<std::byte, Sesame::SECRET_SIZE> secret;
	registration_callback_t on_registration_callback{};
	bool registered = false;

	void handle_registration(const Sesame::os3_registration_t& cmd);
};

}  // namespace libsesame3bt::core
