#include "SesameClientCoreImpl.h"
#include <mbedtls/cmac.h>
#include <mbedtls/ecdh.h>
#include <cinttypes>
#include "libsesame3bt/ClientCore.h"
#include "libsesame3bt/util.h"

#ifndef LIBSESAME3BTCORE_DEBUG
#define LIBSESAME3BTCORE_DEBUG 0
#endif
#include "debug.h"

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

}  // namespace

using util::to_cptr;
using util::to_ptr;

using model_t = Sesame::model_t;

SesameClientCoreImpl::SesameClientCoreImpl(SesameClientBackend& backend, SesameClientCore& core) : backend(backend), core(core) {}

SesameClientCoreImpl::~SesameClientCoreImpl() {}

void
SesameClientCoreImpl::reset_session() {
	ccm_ctx.reset();
	is_key_shared = false;
}

void
SesameClientCoreImpl::disconnect() {
	backend.disconnect();
	reset_session();
	update_state(state_t::idle);
}

bool
SesameClientCoreImpl::begin(model_t model) {
	this->model = model;
	switch (model) {
		case model_t::sesame_3:
		case model_t::sesame_bot:
		case model_t::sesame_bike:
		case model_t::sesame_4:
			handler.emplace(std::in_place_type<OS2Handler>, this);
			break;
		case model_t::sesame_5:
		case model_t::sesame_bike_2:
		case model_t::sesame_5_pro:
		case model_t::open_sensor_1:
		case model_t::sesame_touch_pro:
		case model_t::sesame_touch:
			handler.emplace(std::in_place_type<OS3Handler>, this);
			break;
		default:
			DEBUG_PRINTF("%u: model not supported\n", static_cast<uint8_t>(model));
			return false;
	}
	if (!handler->init()) {
		handler.reset();
		return false;
	}
	return true;
}

bool
SesameClientCoreImpl::set_keys(std::string_view pk_str, std::string_view secret_str) {
	if (!handler) {
		DEBUG_PRINTLN("begin() not finished");
		return false;
	}
	return handler->set_keys(pk_str, secret_str);
}

bool
SesameClientCoreImpl::set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
                               const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key) {
	if (!handler) {
		DEBUG_PRINTLN("begin() not finished");
		return false;
	}
	return handler->set_keys(public_key, secret_key);
}

void
SesameClientCoreImpl::update_state(state_t new_state) {
	if (state.exchange(new_state) == new_state) {
		return;
	}
	if (state_callback) {
		state_callback(core, new_state);
	}
}

bool
SesameClientCoreImpl::send_data(std::byte* pkt, size_t pkt_size, bool is_crypted) {
	std::array<std::byte, 1 + FRAGMENT_SIZE> fragment;  // 1 for header
	int pos = 0;
	for (size_t remain = pkt_size; remain > 0;) {
		fragment[0] = packet_header_t{
		    pos == 0,
		    remain > FRAGMENT_SIZE ? packet_kind_t::not_finished
		    : is_crypted           ? packet_kind_t::encrypted
		                           : packet_kind_t::plain,
		    std::byte{0}}.value;
		size_t ssz = std::min(remain, FRAGMENT_SIZE);
		std::copy(pkt + pos, pkt + pos + ssz, &fragment[1]);
		if (!backend.write_to_tx(to_cptr(fragment), ssz + 1)) {
			DEBUG_PRINTLN("Failed to send data to the device");
			return false;
		}
		pos += ssz;
		remain -= ssz;
	}
	return true;
}

bool
SesameClientCoreImpl::decrypt(const std::byte* in, size_t in_len, std::byte* out, size_t out_size) {
	if (in_len < CMAC_TAG_SIZE || out_size < in_len - CMAC_TAG_SIZE) {
		return false;
	}
	int mbrc;
	if ((mbrc = mbedtls_ccm_auth_decrypt(&ccm_ctx, in_len - CMAC_TAG_SIZE, to_cptr(dec_iv), dec_iv.size(), to_cptr(auth_add_data),
	                                     auth_add_data.size(), to_cptr(in), to_ptr(out), to_cptr(&in[in_len - CMAC_TAG_SIZE]),
	                                     CMAC_TAG_SIZE)) != 0) {
		DEBUG_PRINTF("%d: auth_decrypt failed\n", mbrc);
		return false;
	}
	handler->update_dec_iv();
	return true;
}

bool
SesameClientCoreImpl::encrypt(const std::byte* in, size_t in_len, std::byte* out, size_t out_size) {
	if (out_size < in_len + CMAC_TAG_SIZE) {
		return false;
	}
	int rc;
	if ((rc = mbedtls_ccm_encrypt_and_tag(&ccm_ctx, in_len, to_cptr(enc_iv), enc_iv.size(), to_cptr(auth_add_data),
	                                      auth_add_data.size(), to_cptr(in), to_ptr(out), to_ptr(&out[in_len]), CMAC_TAG_SIZE)) !=
	    0) {
		DEBUG_PRINTF("%d: encrypt_and_tag failed\n", rc);
	}
	handler->update_enc_iv();
	return true;
}

void
SesameClientCoreImpl::on_received(const std::byte* p, size_t len) {
	if (len <= 1) {
		return;
	}
	packet_header_t h;
	h.value = p[0];
	if (h.is_start) {
		skipping = false;
		recv_size = 0;
	}
	if (skipping) {
		if (h.kind == SesameClientCoreImpl::packet_kind_t::encrypted) {
			handler->update_dec_iv();
		}
		return;
	}
	if (recv_size + len - 1 > MAX_RECV) {
		DEBUG_PRINTLN("Received data too long, skipping");
		skipping = true;
		if (h.kind == SesameClientCoreImpl::packet_kind_t::encrypted) {
			handler->update_dec_iv();
		}
		return;
	}
	std::copy(p + 1, p + len, &recv_buffer[recv_size]);
	recv_size += len - 1;
	if (h.kind == packet_kind_t::not_finished) {
		// wait next packet
		return;
	}
	skipping = true;
	if (h.kind == packet_kind_t::encrypted) {
		if (recv_size < CMAC_TAG_SIZE) {
			DEBUG_PRINTLN("Encrypted message too short");
			return;
		}
		if (!is_key_shared) {
			DEBUG_PRINTLN("Encrypted message received before key sharing");
			return;
		}
		std::array<std::byte, MAX_RECV - CMAC_TAG_SIZE> decrypted{};
		if (!decrypt(recv_buffer.data(), recv_size, &decrypted[0], recv_size - CMAC_TAG_SIZE)) {
			return;
		}
		std::copy(decrypted.cbegin(), decrypted.cbegin() + recv_size - CMAC_TAG_SIZE, &recv_buffer[0]);
		recv_size -= CMAC_TAG_SIZE;
	} else if (h.kind != packet_kind_t::plain) {
		DEBUG_PRINTF("%u: Unexpected packet kind\n", static_cast<uint8_t>(h.kind));
		return;
	}
	if (recv_size < sizeof(Sesame::message_header_t)) {
		DEBUG_PRINTF("%u: Short notification, ignore\n", recv_size);
		return;
	}
	auto msg = reinterpret_cast<const Sesame::message_header_t*>(recv_buffer.data());
	switch (msg->op_code) {
		case Sesame::op_code_t::publish:
			switch (msg->item_code) {
				case Sesame::item_code_t::initial:
					handle_publish_initial();
					break;
				case Sesame::item_code_t::mech_setting:
					handler->handle_publish_mecha_setting(&recv_buffer[sizeof(Sesame::message_header_t)],
					                                      recv_size - sizeof(Sesame::message_header_t));
					break;
				case Sesame::item_code_t::mech_status:
					handler->handle_mecha_status(&recv_buffer[sizeof(Sesame::message_header_t)],
					                             recv_size - sizeof(Sesame::message_header_t));
					break;
				default:
					DEBUG_PRINTF("%u: Unsupported item on publish\n", static_cast<uint8_t>(msg->item_code));
					break;
			}
			break;
		case Sesame::op_code_t::response:
			switch (msg->item_code) {
				case Sesame::item_code_t::login:
					handle_response_login();
					break;
				case Sesame::item_code_t::mech_status:
					handler->handle_mecha_status(&recv_buffer[sizeof(Sesame::message_header_t) + 1],
					                             recv_size - sizeof(Sesame::message_header_t) - 1);
					break;
				case Sesame::item_code_t::history:
					if (history_callback) {
						handler->handle_history(&recv_buffer[sizeof(Sesame::message_header_t)], recv_size - sizeof(Sesame::message_header_t));
					}
					break;
				default:
					DEBUG_PRINTF("%u: Unsupported item on response\n", static_cast<uint8_t>(msg->item_code));
					break;
			}
			break;
		default:
			DEBUG_PRINTF("%u: Unexpected op code\n", static_cast<uint8_t>(msg->op_code));
			break;
	}
}

void
SesameClientCoreImpl::handle_publish_initial() {
	if (get_state() == state_t::authenticating) {
		DEBUG_PRINTLN("skipped repeating initial");
		return;
	}
	handler->handle_publish_initial(&recv_buffer[sizeof(Sesame::message_header_t)], recv_size - sizeof(Sesame::message_header_t));
	return;
}

void
SesameClientCoreImpl::handle_response_login() {
	handler->handle_response_login(&recv_buffer[sizeof(Sesame::message_header_t)], recv_size - sizeof(Sesame::message_header_t));
	return;
}

bool
SesameClientCoreImpl::request_history() {
	std::byte flag{0};
	return handler->send_command(Sesame::op_code_t::read, Sesame::item_code_t::history, &flag, sizeof(flag), true);
}

void
SesameClientCoreImpl::fire_history_callback(const History& history) {
	if (history_callback) {
		history_callback(core, history);
	}
}

bool
SesameClientCoreImpl::send_cmd_with_tag(Sesame::item_code_t code, std::string_view tag) {
	std::array<char, 1 + Handler::MAX_HISTORY_TAG_SIZE> tagchars{};
	auto truncated = util::truncate_utf8(tag, handler->get_max_history_tag_size());
	tagchars[0] = std::size(truncated);
	std::copy(std::begin(truncated), std::end(truncated), &tagchars[1]);
	auto tagbytes = reinterpret_cast<std::byte*>(tagchars.data());
	return handler->send_command(Sesame::op_code_t::async, code, tagbytes, handler->get_cmd_tag_size(tagbytes), true);
}

bool
SesameClientCoreImpl::unlock(std::string_view tag) {
	if (!is_session_active()) {
		DEBUG_PRINTLN("Cannot operate while session is not active");
		return false;
	}
	return send_cmd_with_tag(Sesame::item_code_t::unlock, tag);
}

bool
SesameClientCoreImpl::lock(std::string_view tag) {
	if (model == model_t::sesame_bike || model == model_t::sesame_bike_2) {
		DEBUG_PRINTLN("SESAME Bike do not support locking");
		return false;
	}
	if (!is_session_active()) {
		DEBUG_PRINTLN("Cannot operate while session is not active");
		return false;
	}
	return send_cmd_with_tag(Sesame::item_code_t::lock, tag);
}

bool
SesameClientCoreImpl::click(std::string_view tag) {
	if (model != model_t::sesame_bot) {
		DEBUG_PRINTLN("click is supported only on SESAME bot");
		return false;
	}
	if (!is_session_active()) {
		DEBUG_PRINTLN("Cannot operate while session is not active");
		return false;
	}
	return send_cmd_with_tag(Sesame::item_code_t::click, tag);
}

void
SesameClientCoreImpl::fire_status_callback() {
	if (lock_status_callback) {
		lock_status_callback(core, sesame_status);
	}
}

void
SesameClientCoreImpl::on_disconnected() {
	if (state.load() != state_t::idle) {
		DEBUG_PRINTLN("Bluetooth disconnected by peer");
		reset_session();
		update_state(state_t::idle);
	}
}

bool
SesameClientCoreImpl::has_setting() const {
	switch (model) {
		case model_t::open_sensor_1:  // may be
		case model_t::sesame_touch:
		case model_t::sesame_touch_pro:  // may be
			return false;
		default:
			return true;
	}
}

void
SesameClientCoreImpl::request_status() {
	handler->send_command(Sesame::op_code_t::read, Sesame::item_code_t::mech_status, nullptr, 0, true);
}

}  // namespace libsesame3bt::core
