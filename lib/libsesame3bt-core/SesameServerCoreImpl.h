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
	bool begin(libsesame3bt::Sesame::model_t model, const uint8_t (&uuid)[16]);
	void update();

	void on_subscribed();
	bool generate_keypair();
	bool load_key(const std::array<std::byte, 32>& privkey);
	void on_received(const std::byte* data, size_t size);
	void on_disconnected();
	bool export_keypair(std::array<std::byte, 64>& pubkey, std::array<std::byte, 32>& privkey);
	bool set_registered(const std::array<std::byte, Sesame::SECRET_SIZE>& secret);
	bool is_registered() const { return registered; }
	bool prepare_session_key();

	void set_on_registration_callback(registration_callback_t callback) { on_registration_callback = callback; }
	void set_on_command_callback(command_callback_t callback) { on_command_callback = callback; }

	std::tuple<std::string, std::string> create_advertisement_data_os3();

 private:
	enum class state_t { idle, waiting_login };
	SesameServerCore& core;
	SesameBLETransport transport;
	CryptHandler crypt{std::in_place_type<OS3IVHandler>};
	std::byte nonce[4];
	Ecc ecc;
	std::array<std::byte, Sesame::SECRET_SIZE> secret;
	registration_callback_t on_registration_callback{};
	command_callback_t on_command_callback{};
	bool registered = false;
	Sesame::model_t model = Sesame::model_t::unknown;
	uint8_t uuid[16];
	state_t state = state_t::idle;
	uint32_t last_state_changed = 0;

	void handle_registration(const std::byte* payload, size_t size);
	void handle_login(const std::byte* payload, size_t size);
	void handle_cmd_with_tag(Sesame::item_code_t cmd, const std::byte* payload, size_t size);

	void set_state(state_t state);
	void send_initial();
};

}  // namespace libsesame3bt::core
