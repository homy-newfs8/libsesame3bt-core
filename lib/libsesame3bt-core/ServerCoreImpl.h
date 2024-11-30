#pragma once
#include <cstddef>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>
#include "Sesame.h"
#include "crypt.h"
#include "crypt_ecc.h"
#include "libsesame3bt/BLEBackend.h"
#include "libsesame3bt/ServerCore.h"
#include "transport.h"

namespace libsesame3bt::core {

enum class session_state_t { idle, waiting_login, running };

class SesameServerCoreImpl;

class ServerSession : SesameBLEBackend {
 public:
	ServerSession(ServerBLEBackend& backend, uint16_t session_id) : backend(backend), session_id(session_id), transport(*this) {}
	virtual ~ServerSession() = default;

 private:
	friend class SesameServerCoreImpl;
	CryptHandler crypt{std::in_place_type<OS3IVHandler>, true};
	std::byte nonce[4];
	session_state_t state = session_state_t::idle;
	uint32_t last_state_changed = 0;
	ServerBLEBackend& backend;
	const uint16_t session_id;
	SesameBLETransport transport;
	virtual bool write_to_tx(const uint8_t* data, size_t size) override { return backend.write_to_central(session_id, data, size); };
	virtual void disconnect() override { backend.disconnect(session_id); }
	void set_state(session_state_t state);
};

class SesameServerCoreImpl {
 public:
	SesameServerCoreImpl(ServerBLEBackend& backend, SesameServerCore& core, size_t max_sessions);
	bool begin(libsesame3bt::Sesame::model_t model, const uint8_t (&uuid)[16]);
	void update();
	bool set_registered(const std::array<std::byte, Sesame::SECRET_SIZE>& secret);
	bool is_registered() const { return registered; }
	size_t get_session_count() const;
	bool send_notify(std::optional<uint16_t> session_id,
	                 Sesame::op_code_t op_code,
	                 Sesame::item_code_t item_code,
	                 const std::byte* data,
	                 size_t size);

	bool on_subscribed(uint16_t session_id);
	bool on_received(uint16_t session_id, const std::byte* data, size_t size);
	void on_disconnected(uint16_t session_id);

	void set_on_registration_callback(registration_callback_t callback) { on_registration_callback = callback; }
	void set_on_command_callback(command_callback_t callback) { on_command_callback = callback; }
	void set_authentication_timeout(uint32_t timeout_msec) { auth_timeout = timeout_msec; }

	std::tuple<std::string, std::string> create_advertisement_data_os3() const;

 private:
	static constexpr uint32_t DEFAULT_AUTH_TIMEOUT_MSEC = 10'000;

	SesameServerCore& core;
	ServerBLEBackend& ble_backend;
	Ecc ecc;
	registration_callback_t on_registration_callback{};
	command_callback_t on_command_callback{};
	bool registered = false;
	Sesame::model_t model = Sesame::model_t::unknown;
	uint8_t uuid[16];
	std::array<std::byte, Sesame::SECRET_SIZE> secret;
	std::vector<std::pair<std::optional<uint16_t>, std::optional<ServerSession>>> vsessions;
	uint32_t auth_timeout = DEFAULT_AUTH_TIMEOUT_MSEC;

	bool handle_registration(ServerSession& session, const std::byte* payload, size_t size);
	bool handle_login(ServerSession& session, const std::byte* payload, size_t size);
	bool handle_cmd_with_tag(ServerSession& session, Sesame::item_code_t cmd, const std::byte* payload, size_t size);
	bool prepare_session_key(ServerSession& session);
	ServerSession* create_session(uint16_t session_id);
	ServerSession* get_session(uint16_t session_id);

	bool send_initial(ServerSession& session);
};

}  // namespace libsesame3bt::core
