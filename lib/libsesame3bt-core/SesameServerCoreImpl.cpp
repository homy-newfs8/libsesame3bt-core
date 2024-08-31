#include "SesameServerCoreImpl.h"
#include <mbedtls/base64.h>
#include <string_view>
#include "Sesame.h"
#include "debug.h"
#include "libsesame3bt/util.h"

namespace libsesame3bt::core {

namespace {

constexpr size_t CMAC_TAG_SIZE = 4;
constexpr size_t AES_KEY_SIZE = 16;
constexpr size_t FRAGMENT_SIZE = 19;
constexpr size_t AUTH_TAG_TRUNCATED_SIZE = 4;
constexpr size_t KEY_INDEX_SIZE = 2;
constexpr size_t ADD_DATA_SIZE = 1;
constexpr size_t TOKEN_SIZE = Sesame::TOKEN_SIZE;
constexpr size_t IV_COUNTER_SIZE = 5;
constexpr size_t REGISTERED_DEVICE_DATA_SIZE = 23;

constexpr uint32_t SEND_INITIAL_INTERVAL = 0;

template <typename T>
const std::byte*
to_bytes(const T* t) {
	return reinterpret_cast<const std::byte*>(t);
}

}  // namespace

using util::to_byte;
using util::to_cptr;
using util::to_ptr;

SesameServerCoreImpl::SesameServerCoreImpl(SesameBLEBackend& backend, SesameServerCore& core) : core(core), transport(backend) {}

bool
SesameServerCoreImpl::begin(Sesame::model_t model, const uint8_t (&uuid)[16]) {
	this->model = model;
	std::copy(std::cbegin(uuid), std::cend(uuid), std::begin(this->uuid));

	return false;
}

bool
SesameServerCoreImpl::generate_keypair() {
	if (!ecc.generate_keypair()) {
		return false;
	}
	return true;
}

void
SesameServerCoreImpl::send_initial() {
	DEBUG_PRINTLN("send publish/initial");
	Sesame::publish_initial_t msg;
	std::copy(std::cbegin(nonce), std::cend(nonce), msg.token);
	if (!transport.send_notify(Sesame::op_code_t::publish, Sesame::item_code_t::initial, reinterpret_cast<const std::byte*>(&msg),
	                           sizeof(msg), false, crypt)) {
		DEBUG_PRINTLN("Failed to publish initial");
	}
}

void
SesameServerCoreImpl::on_subscribed() {
	Random::get_random(nonce);
	send_initial();
	if (is_registered()) {
		if (!prepare_session_key()) {
			return;
		}
	}
	state = state_t::waiting_login;
}

void
SesameServerCoreImpl::on_received(const std::byte* data, size_t size) {
	using decode_result_t = SesameBLETransport::decode_result_t;
	DEBUG_PRINTLN("received %u", size);
	auto rc = transport.decode(data, size, crypt);
	if (rc != decode_result_t::received) {
		return;
	}
	data = transport.data();
	size = transport.data_size();

	if (size < 1) {
		DEBUG_PRINTLN("Too short command ignored");
		return;
	}
	using item_code_t = Sesame::item_code_t;
	auto code = static_cast<item_code_t>(data[0]);
	switch (code) {
		case item_code_t::registration:
			handle_registration(data + 1, size - 1);
			break;
		case item_code_t::login:
			handle_login(data + 1, size - 1);
			break;
		case item_code_t::lock:
		case item_code_t::unlock:
		case item_code_t::click:
			handle_cmd_with_tag(code, data + 1, size - 1);
			break;
		default:
			DEBUG_PRINTLN("Unhandled item %u", static_cast<uint8_t>(code));
			break;
	}
}

void
SesameServerCoreImpl::on_disconnected() {}

void
SesameServerCoreImpl::handle_registration(const std::byte* payload, size_t size) {
	if (size != sizeof(Sesame::os3_cmd_registration_t)) {
		DEBUG_PRINTLN("%u: registration packet length mismatch, ignored", size);
		return;
	}
	if (is_registered()) {
		DEBUG_PRINTLN("Already registered, registration ignored");
		return;
	}
	if (!on_registration_callback) {
		DEBUG_PRINTLN("Registration callback not set, abort registration");
		return;
	}
	auto* cmd = reinterpret_cast<const Sesame::os3_cmd_registration_t*>(payload);
	DEBUG_PRINTLN("registration time=%u", cmd->timestamp);
	if (!ecc.derive_secret(cmd->public_key, secret)) {
		return;
	}
	if (!prepare_session_key()) {
		return;
	}
	if (on_registration_callback) {
		on_registration_callback(secret);
	}
	Sesame::response_registration_5_t resp{};
	if (!ecc.export_pk(resp.public_key)) {
		return;
	}
	DEBUG_PRINTLN("sending registration response (%u)", sizeof(resp));
	if (!transport.send_notify(Sesame::op_code_t::response, Sesame::item_code_t::registration, to_bytes(&resp), sizeof(resp), false,
	                           crypt)) {
		return;
	}
	DEBUG_PRINTLN("registration done");
}

void
SesameServerCoreImpl::handle_login(const std::byte* payload, size_t size) {
	DEBUG_PRINTLN("handle_login");
	if (size != sizeof(Sesame::os3_cmd_login_t)) {
		DEBUG_PRINTLN("login payload length mismatch");
		return;
	}
	if (!crypt.is_key_shared()) {
		DEBUG_PRINTLN("login invalid state");
		return;
	}
	if (!crypt.verify_auth_code(payload)) {
		DEBUG_PRINTLN("authentication failed");
		return;
	}
	Sesame::response_login_5_t resp{};
	if (!transport.send_notify(Sesame::op_code_t::response, Sesame::item_code_t::login, to_bytes(&resp), sizeof(resp), true, crypt)) {
		DEBUG_PRINTLN("Failed to send login response");
	}
	Sesame::mecha_status_5_t status{};
	status.in_lock = true;
	status.battery = 6.2 * 500;
	if (!transport.send_notify(Sesame::op_code_t::publish, Sesame::item_code_t::mech_status, to_bytes(&status), sizeof(status), true,
	                           crypt)) {
		DEBUG_PRINTLN("Failed to send mecha status");
	}
	Sesame::mecha_setting_5_t settings{};
	settings.lock_position = 20263;
	settings.unlock_position = 20157;
	if (!transport.send_notify(Sesame::op_code_t::publish, Sesame::item_code_t::mech_setting, to_bytes(&settings), sizeof(settings),
	                           true, crypt)) {
		DEBUG_PRINTLN("Failed to send mecha setting");
	}
}

void
SesameServerCoreImpl::handle_cmd_with_tag(Sesame::item_code_t cmd, const std::byte* payload, size_t size) {
	DEBUG_PRINTLN("handle_cmd");
	if (size == 0) {
		DEBUG_PRINTLN("Too short command, ignored");
		return;
	}
	auto tstr = std::string(reinterpret_cast<const char*>(payload + 1), static_cast<size_t>(payload[0]));
	const char* cmd_str = cmd == Sesame::item_code_t::lock ? "lock" : cmd == Sesame::item_code_t::unlock ? "unlock" : "click";
	DEBUG_PRINTLN("cmd=%s(%s)", cmd_str, tstr.c_str());
	Sesame::response_os3_t res;
	if (on_command_callback) {
		res.result = on_command_callback(cmd, tstr);
	} else {
		res.result = Sesame::result_code_t::not_supported;
	}
	if (!transport.send_notify(Sesame::op_code_t::response, cmd, to_bytes(&res), sizeof(res), true, crypt)) {
		DEBUG_PRINTLN("Failed to send response to cmd");
	}
}

void
SesameServerCoreImpl::set_state(state_t state) {
	if (this->state == state) {
		return;
	}
	this->state = state;
	this->last_state_changed = millis();
}

bool
SesameServerCoreImpl::export_keypair(std::array<std::byte, Sesame::PK_SIZE>& pubkey, std::array<std::byte, 32>& privkey) {
	bool rc = ecc.export_pk(pubkey);
	if (rc) {
		rc = ecc.convert_sk_to_binary(ecc.sk, privkey);
	}
	return rc;
}

bool
SesameServerCoreImpl::set_registered(const std::array<std::byte, Sesame::SECRET_SIZE>& new_secret) {
	std::copy(std::cbegin(new_secret), std::cend(new_secret), std::begin(secret));
	registered = true;
	return true;
}

bool
SesameServerCoreImpl::prepare_session_key() {
	CmacAes128 cmac;
	std::array<std::byte, Sesame::SECRET_SIZE> session_key;
	if (!cmac.set_key(secret) || !cmac.update(nonce) || !cmac.finish(session_key)) {
		DEBUG_PRINTLN("Failed to generate session key");
		return false;
	}
	if (!crypt.set_session_key(session_key.data(), session_key.size(), {}, nonce)) {
		DEBUG_PRINTLN("Failed to init session");
		return false;
	}
	return true;
}

/**
 * @brief Create data for BLE advertisement.
 *
 * @return tuple of "manufacturer data" and "local name"
 */
std::tuple<std::string, std::string>
SesameServerCoreImpl::create_advertisement_data_os3() {
	DEBUG_PRINTLN("c uuid=%s", util::bin2hex(uuid).c_str());
	std::string manu;
	manu.push_back(static_cast<char>(Sesame::COMPANY_ID & 0xff));
	manu.push_back(static_cast<char>(Sesame::COMPANY_ID >> 8));
	manu.push_back(static_cast<char>(model));
	manu.push_back(0);
	manu.push_back(static_cast<char>(registered ? 1 : 0));
	manu.append(std::cbegin(uuid), std::cend(uuid));

	uint8_t b64[25];
	size_t out_len;
	if (int mbrc = mbedtls_base64_encode(b64, sizeof(b64), &out_len, uuid, sizeof(uuid)); mbrc != 0) {
		DEBUG_PRINTLN("This cannot be happened...");
	}
	std::string name{reinterpret_cast<const char*>(b64), 22};
	return std::make_tuple(manu, name);
}

bool
SesameServerCoreImpl::load_key(const std::array<std::byte, 32>& privkey) {
	return ecc.load_key(privkey);
}

void
SesameServerCoreImpl::update() {
	switch (state) {
		case state_t::waiting_login:
			if (SEND_INITIAL_INTERVAL) {
				if (auto elapsed = millis() - last_state_changed; elapsed > SEND_INITIAL_INTERVAL) {
					send_initial();
					last_state_changed = millis();
				}
			}
			break;
	}
}

}  // namespace libsesame3bt::core
