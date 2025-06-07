#include "ClientCoreImpl.h"
#include <mbedtls/base64.h>
#include <cinttypes>
#include "libsesame3bt/ClientCore.h"
#include "libsesame3bt/util.h"

#ifndef LIBSESAME3BTCORE_DEBUG
#define LIBSESAME3BTCORE_DEBUG 0
#endif
#include "debug.h"

namespace libsesame3bt::core {

namespace {

constexpr size_t REGISTERED_DEVICE_DATA_SIZE = 23;

}  // namespace

using util::to_cptr;
using util::to_ptr;

using model_t = Sesame::model_t;

SesameClientCoreImpl::SesameClientCoreImpl(SesameBLEBackend& backend, SesameClientCore& core) : transport(backend), core(core) {}

SesameClientCoreImpl::~SesameClientCoreImpl() {}

void
SesameClientCoreImpl::disconnect() {
	transport.disconnect();
	if (crypt) {
		crypt->reset_session_key();
	}
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
			crypt.emplace(std::in_place_type<OS2IVHandler>);
			handler.emplace(std::in_place_type<OS2Handler>, this, transport, *crypt);
			break;
		case model_t::sesame_5:
		case model_t::sesame_bike_2:
		case model_t::sesame_5_pro:
		case model_t::open_sensor_1:
		case model_t::sesame_touch_pro:
		case model_t::sesame_touch:
		case model_t::remote:
		case model_t::remote_nano:
		case model_t::sesame_bot_2:
		case model_t::sesame_face_pro:
		case model_t::sesame_face:
			crypt.emplace(std::in_place_type<OS3IVHandler>);
			handler.emplace(std::in_place_type<OS3Handler>, this, transport, *crypt);
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

void
SesameClientCoreImpl::on_received(const std::byte* p, size_t len) {
	if (!handler) {
		DEBUG_PRINTLN("begin() not finished");
		return;
	}
	auto rc = transport.decode(p, len, *crypt);
	if (rc != SesameBLETransport::decode_result_t::received) {
		return;
	}
	auto recv_size = transport.data_size();
	if (recv_size < sizeof(Sesame::message_header_t)) {
		DEBUG_PRINTLN("too short message dropped");
		return;
	}
	auto* msg = reinterpret_cast<const Sesame::message_header_t*>(transport.data());
	auto* body = transport.data() + sizeof(Sesame::message_header_t);
	switch (msg->op_code) {
		case Sesame::op_code_t::publish:
			switch (msg->item_code) {
				case Sesame::item_code_t::initial:
					handle_publish_initial();
					break;
				case Sesame::item_code_t::mech_setting:
					handler->handle_publish_mecha_setting(body, recv_size - sizeof(Sesame::message_header_t));
					break;
				case Sesame::item_code_t::mech_status:
					handler->handle_publish_mecha_status(body, recv_size - sizeof(Sesame::message_header_t));
					break;
				case Sesame::item_code_t::pub_ssm_key:
					handle_publish_pub_key_sesame(body, recv_size - sizeof(Sesame::message_header_t));
					break;
				default:
					DEBUG_PRINTLN("%u: Unsupported item on publish: %s", static_cast<uint8_t>(msg->item_code),
					              util::bin2hex(transport.data() + 1, transport.data_size() - 1).c_str());
					break;
			}
			break;
		case Sesame::op_code_t::response:
			switch (msg->item_code) {
				case Sesame::item_code_t::login:
					handler->handle_response_login(transport.data() + sizeof(Sesame::message_header_t),
					                               transport.data_size() - sizeof(Sesame::message_header_t));
					break;
				case Sesame::item_code_t::mech_status:
					handler->handle_response_mecha_status(body, recv_size - sizeof(Sesame::message_header_t));
					break;
				case Sesame::item_code_t::history:
					if (history_callback) {
						handler->handle_history(body, recv_size - sizeof(Sesame::message_header_t));
					}
					break;
				default:
					DEBUG_PRINTLN("%u: Unsupported item on response: %s", static_cast<uint8_t>(msg->item_code),
					              util::bin2hex(transport.data() + 1, transport.data_size() - 1).c_str());
					break;
			}
			break;
		default:
			DEBUG_PRINTLN("%u: Unexpected op code", static_cast<uint8_t>(msg->op_code));
			break;
	}
}

void
SesameClientCoreImpl::handle_publish_initial() {
	if (get_state() == state_t::authenticating) {
		DEBUG_PRINTLN("skipped repeating initial");
		return;
	}
	handler->handle_publish_initial(transport.data() + sizeof(Sesame::message_header_t),
	                                transport.data_size() - sizeof(Sesame::message_header_t));
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
	if (model == Sesame::model_t::sesame_bot_2) {
		tagchars[0] = 0;
	} else {
		auto truncated = util::truncate_utf8(tag, handler->get_max_history_tag_size());
		tagchars[0] = std::size(truncated);
		std::copy(std::begin(truncated), std::end(truncated), &tagchars[1]);
	}
	auto tagbytes = reinterpret_cast<std::byte*>(tagchars.data());
	return handler->send_command(Sesame::op_code_t::async, code, tagbytes,
	                             handler->get_cmd_tag_size(std::to_integer<size_t>(tagbytes[0])), true);
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
	if (model == model_t::sesame_bike) {
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

bool
SesameClientCoreImpl::click(const std::optional<uint8_t> script_no) {
	if (model != model_t::sesame_bot && model != model_t::sesame_bot_2) {
		DEBUG_PRINTLN("click is supported only on SESAME bot");
		return false;
	}
	if (!is_session_active()) {
		DEBUG_PRINTLN("Cannot operate while session is not active");
		return false;
	}
	if (model == Sesame::model_t::sesame_bot) {
		if (script_no == 0) {
			return unlock("");
		} else if (script_no == 1) {
			return lock("");
		} else {
			return send_cmd_with_tag(Sesame::item_code_t::click, "");
		}
	} else {
		if (script_no.has_value()) {
			auto v = script_no.value();
			return handler->send_command(Sesame::op_code_t::async, Sesame::item_code_t::click, reinterpret_cast<const std::byte*>(&v),
			                             sizeof(v), true);
		} else {
			return handler->send_command(Sesame::op_code_t::async, Sesame::item_code_t::click, nullptr, 0, true);
		}
	}
}

void
SesameClientCoreImpl::fire_status_callback() {
	if (lock_status_callback) {
		lock_status_callback(core, sesame_status);
	}
}

void
SesameClientCoreImpl::on_disconnected() {
	transport.reset();
	if (crypt) {
		crypt->reset_session_key();
	}
	if (state.load() != state_t::idle) {
		DEBUG_PRINTLN("Bluetooth disconnected by peer");
		update_state(state_t::idle);
	}
}

bool
SesameClientCoreImpl::has_setting() const {
	switch (model) {
		case model_t::open_sensor_1:  // may be
		case model_t::sesame_touch:
		case model_t::sesame_touch_pro:  // may be
		case model_t::remote:
		case model_t::remote_nano:
		case model_t::sesame_bot_2:
		case model_t::sesame_face_pro:  // may be
		case model_t::sesame_face:
			return false;
		default:
			return true;
	}
}

void
SesameClientCoreImpl::request_status() {
	handler->send_command(Sesame::op_code_t::read, Sesame::item_code_t::mech_status, nullptr, 0, true);
}

void
SesameClientCoreImpl::handle_publish_pub_key_sesame(const std::byte* in, size_t in_size) {
	if (!registered_devices_callback) {
		return;
	}
	int ndevices = in_size / REGISTERED_DEVICE_DATA_SIZE;
	auto regs = std::vector<RegisteredDevice>();
	for (auto i = 0; i < ndevices; i++) {
		const auto* top = in + REGISTERED_DEVICE_DATA_SIZE * i;
		if (top[22] == std::byte{0}) {
			continue;
		}
		if (top[21] == std::byte{0}) {
			// OS3
			RegisteredDevice dev;
			std::copy(top, top + std::size(dev.uuid), reinterpret_cast<std::byte*>(dev.uuid));
			dev.os_ver = Sesame::os_ver_t::os3;
			regs.push_back(dev);
		} else {
			// OS2
			uint8_t b64[22 + 2];
			std::copy(top, top + 22, reinterpret_cast<std::byte*>(b64));
			b64[22] = b64[23] = '=';  // not nul terminated
			size_t idlen;
			RegisteredDevice dev;
			int rc = mbedtls_base64_decode(dev.uuid, sizeof(dev.uuid), &idlen, b64, sizeof(b64));
			if (rc != 0 || idlen != sizeof(dev.uuid)) {
				DEBUG_PRINTF("%s: Failed to decode registered device (OS2)\n", util::bin2hex(b64).c_str());
				continue;
			}
			dev.os_ver = Sesame::os_ver_t::os2;
			regs.push_back(dev);
		}
	}
	registered_devices_callback(core, regs);
}

}  // namespace libsesame3bt::core
