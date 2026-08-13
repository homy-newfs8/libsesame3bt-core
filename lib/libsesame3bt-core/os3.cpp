#include "os3.h"
#include "ClientCoreImpl.h"
#include "Sesame.h"
#include "libsesame3bt/util.h"

#ifndef LIBSESAME3BTCORE_DEBUG
#define LIBSESAME3BTCORE_DEBUG 0
#endif
#include "debug.h"

namespace libsesame3bt::core {

using util::to_byte;
using util::to_cptr;
using util::to_ptr;

result_t
OS3Handler::set_keys(std::string_view pk_str, std::string_view secret_str) {
	if (!util::hex2bin(secret_str, sesame_secret)) {
		DEBUG_PRINTLN("secret_str invalid format");
		return result_t::invalid_argument;
	}
	client->_is_key_set = true;
	return result_t::success;
}

result_t
OS3Handler::set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
                     const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key) {
	std::copy(std::cbegin(secret_key), std::cend(secret_key), std::begin(sesame_secret));
	client->_is_key_set = true;

	return result_t::success;
}

result_t
OS3Handler::send_command(Sesame::op_code_t op_code,
                         Sesame::item_code_t item_code,
                         const std::byte* data,
                         size_t data_size,
                         bool is_crypted) {
	const size_t pkt_size = 1 + data_size + (is_crypted ? Sesame::CMAC_TAG_SIZE : 0);  // 1 for item, 4 for encrypted tag
	std::byte pkt[pkt_size];
	if (is_crypted) {
		std::byte plain[1 + data_size];
		plain[0] = to_byte(item_code);
		std::copy(data, data + data_size, &plain[1]);
		if (auto rc = crypt.encrypt(plain, sizeof(plain), pkt, sizeof(pkt)); rc != result_t::success) {
			return rc;
		}
	} else {
		pkt[0] = to_byte(item_code);
		std::copy(data, data + data_size, &pkt[1]);
	}

	return transport.send_data(pkt, pkt_size, is_crypted) ? result_t::success : result_t::transport_failure;
}

result_t
OS3Handler::handle_publish_initial(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::publish_initial_t)) {
		DEBUG_PRINTLN("%u: short response initial data", in_len);
		return result_t::invalid_packet;
	}
	const auto* msg = reinterpret_cast<const Sesame::publish_initial_t*>(in);
	CmacAes128 cmac;
	std::array<std::byte, 16> session_key;
	if (!cmac.set_key(sesame_secret) || !cmac.update(msg->token) || !cmac.finish(session_key)) {
		return result_t::crypt_failure;
	}
	if (!crypt.set_session_key(session_key.data(), session_key.size(), {}, msg->token)) {
		return result_t::crypt_failure;
	}
	if (auto rc = send_command(Sesame::op_code_t::async, Sesame::item_code_t::login, session_key.data(), 4, false);
	    rc != result_t::success) {
		return rc;
	}
	client->update_state(state_t::authenticating);
	return result_t::success;
}

result_t
OS3Handler::handle_response_login(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::response_login_5_t)) {
		DEBUG_PRINTLN("short response login message");
		return result_t::invalid_packet;
	}
	auto msg = reinterpret_cast<const Sesame::response_login_5_t*>(in);
	if (msg->result != Sesame::result_code_t::success) {
		DEBUG_PRINTLN("%u: login response was not success", static_cast<uint8_t>(msg->result));
		return result_t::auth_failure;
	}
	time_t t = msg->timestamp;
	struct tm tm;
	gmtime_r(&t, &tm);
	DEBUG_PRINTLN("time=%04d/%02d/%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
	              tm.tm_sec);
	setting_received = !client->has_setting();  // treat as setting received
	status_received = false;

	return result_t::success;
}

result_t
OS3Handler::handle_publish_mecha_setting(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::publish_mecha_setting_5_t)) {
		DEBUG_PRINTLN("%u: Unexpected size of mecha setting, ignored", in_len);
		return result_t::invalid_packet;
	}
	auto msg = reinterpret_cast<const Sesame::publish_mecha_setting_5_t*>(in);
	client->setting.emplace<LockSetting>(msg->setting);
	setting_received = true;
	if (client->state != state_t::active && setting_received && status_received) {
		client->update_state(state_t::active);
	}

	return result_t::success;
}

result_t
OS3Handler::handle_publish_mecha_status(const std::byte* in, size_t in_len) {
	DEBUG_PRINTLN("status: %s", util::bin2hex(in, in_len).c_str());

	// old version of bot2 and bike2 uses dedicated short packet
	if ((client->model == Sesame::model_t::sesame_bot_2 || client->model == Sesame::model_t::sesame_bot_3) &&
	    in_len == sizeof(Sesame::mecha_bot_2_status_t)) {
		const auto* msg = reinterpret_cast<const Sesame::mecha_bot_2_status_t*>(in);
		client->sesame_status = {*msg, client->model};
	} else if (client->model == Sesame::model_t::sesame_bike_2 && in_len == sizeof(Sesame::mecha_bike_2_status_t)) {
		const auto* msg = reinterpret_cast<const Sesame::mecha_bike_2_status_t*>(in);
		client->sesame_status = {*msg, client->model};
	} else {
		if (in_len < sizeof(Sesame::publish_mecha_status_5_t)) {
			DEBUG_PRINTF("%u: Unexpected size of mecha status, ignored", in_len);
			return result_t::invalid_packet;
		}
		const auto* msg = reinterpret_cast<const Sesame::publish_mecha_status_5_t*>(in);
		client->sesame_status = {msg->status, client->model};
	}
	client->fire_status_callback();
	status_received = true;
	if (client->state != state_t::active && setting_received && status_received) {
		client->update_state(state_t::active);
	}

	return result_t::success;
}

result_t
OS3Handler::handle_history(const std::byte* in, size_t in_len) {
	History history{};
	if (in_len < 1) {
		DEBUG_PRINTLN("%u: Unexpected size of history response, ignored", in_len);
		return result_t::invalid_packet;
	}
	history.result = static_cast<Sesame::result_code_t>(in[0]);
	if (history.result != Sesame::result_code_t::success || in_len < sizeof(Sesame::response_history_5_t)) {
		DEBUG_PRINTLN("%u: Empty history", static_cast<uint8_t>(history.result));
		client->fire_history_callback(history);
		return result_t::success;
	}
	const auto* hist = reinterpret_cast<const Sesame::response_history_5_t*>(in);
	history.time = hist->timestamp;
	history.record_id = hist->record_id;
	auto histtype = hist->type;
	if (in_len > sizeof(Sesame::response_history_5_t)) {
		const auto* tag_data = reinterpret_cast<const char*>(in + sizeof(Sesame::response_history_5_t));
		uint8_t tag_len = tag_data[0];
		if (histtype == Sesame::history_type_t::ble_lock || histtype == Sesame::history_type_t::ble_unlock) {
			if (tag_len >= 60) {
				histtype =
				    histtype == Sesame::history_type_t::ble_lock ? Sesame::history_type_t::web_lock : Sesame::history_type_t::web_unlock;
				tag_len %= 30;
			} else if (tag_len >= 30) {
				histtype =
				    histtype == Sesame::history_type_t::ble_lock ? Sesame::history_type_t::wm2_lock : Sesame::history_type_t::wm2_unlock;
				tag_len %= 30;
			}
		}
		tag_len = std::min<uint8_t>(tag_len, get_max_history_tag_size());
		if (tag_len > 0) {
			auto tag_str = util::cleanup_tail_utf8({tag_data + 1, tag_len});
			history.tag_len = tag_str.length();
			*std::copy(std::begin(tag_str), std::end(tag_str), history.tag) = 0;
		} else if (in_len >= sizeof(Sesame::response_history_5_t) + 18) {
			history.history_tag_type = static_cast<history_tag_type_t>(tag_data[1]);
			auto str = util::bin2hex(tag_data + 2, 16);
			history.tag_len = str.length();
			std::copy(str.cbegin(), str.cend(), history.tag);
			if (in_len >= sizeof(Sesame::response_history_5_t) + 20) {
				uint16_t voltage_raw = static_cast<uint8_t>(tag_data[19]) << 8 | static_cast<uint8_t>(tag_data[18]);
				history.scaled_voltage = Status::status_value_to_scaled_voltage_os3(voltage_raw);
				if (in_len >= sizeof(Sesame::response_history_5_t) + 22) {
					uint16_t voltage_raw2 = static_cast<uint8_t>(tag_data[21]) << 8 | static_cast<uint8_t>(tag_data[20]);
					history.scaled_voltage2 = Status::status_value_to_scaled_voltage_os3(voltage_raw2);
					if (in_len >= sizeof(Sesame::response_history_5_t) + 23) {
						history.extra = std::string_view(tag_data + 22, in_len - sizeof(Sesame::response_history_5_t) - 22);
					}
				}
			}
		}
	}
	history.type = histtype;
	client->fire_history_callback(history);

	return result_t::success;
}

}  // namespace libsesame3bt::core
