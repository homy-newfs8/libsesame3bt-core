#include "SesameServerCoreImpl.h"
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
template <typename T>
const std::byte*
to_bytes(const T& t) {
	return reinterpret_cast<const std::byte*>(&t);
}

}  // namespace

using util::to_byte;
using util::to_cptr;
using util::to_ptr;

SesameServerCoreImpl::SesameServerCoreImpl(SesameBLEBackend& backend, SesameServerCore& core) : core(core), transport(backend) {}

bool
SesameServerCoreImpl::generate_keypair() {
	if (!ecc.generate_keypair()) {
		return false;
	}
	return true;
}

void
SesameServerCoreImpl::begin_activation() {
	nonce[0] = std::byte{0};
	nonce[1] = std::byte{1};
	nonce[2] = std::byte{2};
	nonce[3] = std::byte{3};
	Sesame::publish_initial_t msg = {{std::byte{0}, std::byte{1}, std::byte{2}, std::byte{3}}};
	if (!transport.send_notify(Sesame::op_code_t::publish, Sesame::item_code_t::initial, reinterpret_cast<const std::byte*>(&msg),
	                           sizeof(msg), false, crypt)) {
		DEBUG_PRINTLN("Failed to publish initial");
	}
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
	auto* cmd = reinterpret_cast<const Sesame::command_os3_t*>(data);
	using item_code_t = Sesame::item_code_t;
	switch (cmd->item_code) {
		case item_code_t::registration:
			if (size == sizeof(cmd->payload.registration) + 1) {
				handle_registration(cmd->payload.registration);
			} else {
				DEBUG_PRINTLN("%u: registration packet length mismatch, ignored");
			}
			break;
		default:
			DEBUG_PRINTLN("Unhandled item %u", static_cast<uint8_t>(cmd->item_code));
			break;
	}
}
void
SesameServerCoreImpl::on_disconnected() {}

void
SesameServerCoreImpl::handle_registration(const Sesame::os3_registration_t& cmd) {
	if (is_registered()) {
		DEBUG_PRINTLN("Already registered, registration ignored");
		return;
	}
	if (!on_registration_callback) {
		DEBUG_PRINTLN("Registration callback not set, do not register");
		return;
	}
	DEBUG_PRINTLN("registration time=%u", cmd.timestamp);
	if (!ecc.derive_secret(cmd.public_key, secret)) {
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
	if (!transport.send_notify(Sesame::op_code_t::response, Sesame::item_code_t::registration, to_bytes(resp), sizeof(resp), false,
	                           crypt)) {
		return;
	}
	DEBUG_PRINTLN("registration done");
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
SesameServerCoreImpl::load_key(const std::array<std::byte, 32>& privkey) {
	return ecc.load_key(privkey);
}

}  // namespace libsesame3bt::core
