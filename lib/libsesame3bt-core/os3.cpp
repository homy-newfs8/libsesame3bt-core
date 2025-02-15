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

bool
OS3Handler::set_keys(std::string_view pk_str, std::string_view secret_str) {
	if (!util::hex2bin(secret_str, sesame_secret)) {
		DEBUG_PRINTLN("secret_str invalid format");
		return false;
	}
	client->is_key_set = true;
	return true;
}

bool
OS3Handler::set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
                     const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key) {
	std::copy(std::cbegin(secret_key), std::cend(secret_key), std::begin(sesame_secret));
	client->is_key_set = true;

	return true;
}

bool
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
		if (!crypt.encrypt(plain, sizeof(plain), pkt, sizeof(pkt))) {
			return false;
		}
	} else {
		pkt[0] = to_byte(item_code);
		std::copy(data, data + data_size, &pkt[1]);
	}

	return transport.send_data(pkt, pkt_size, is_crypted);
}

void
OS3Handler::handle_publish_initial(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::publish_initial_t)) {
		DEBUG_PRINTLN("%u: short response initial data", in_len);
		client->disconnect();
		return;
	}
	const auto* msg = reinterpret_cast<const Sesame::publish_initial_t*>(in);
	CmacAes128 cmac;
	std::array<std::byte, 16> session_key;
	if (!cmac.set_key(sesame_secret) || !cmac.update(msg->token) || !cmac.finish(session_key)) {
		client->disconnect();
		return;
	}
	if (!crypt.set_session_key(session_key.data(), session_key.size(), {}, msg->token)) {
		client->disconnect();
		return;
	}
	if (send_command(Sesame::op_code_t::async, Sesame::item_code_t::login, session_key.data(), 4, false)) {
		client->update_state(state_t::authenticating);
	} else {
		client->disconnect();
	}
}

void
OS3Handler::handle_response_login(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::response_login_5_t)) {
		DEBUG_PRINTLN("short response login message");
		client->disconnect();
		return;
	}
	auto msg = reinterpret_cast<const Sesame::response_login_5_t*>(in);
	if (msg->result != Sesame::result_code_t::success) {
		DEBUG_PRINTLN("%u: login response was not success", static_cast<uint8_t>(msg->result));
		client->disconnect();
		return;
	}
	time_t t = msg->timestamp;
	struct tm tm;
	gmtime_r(&t, &tm);
	DEBUG_PRINTLN("time=%04d/%02d/%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
	              tm.tm_sec);
	setting_received = !client->has_setting();  // treat as setting received
	status_received = false;
}

void
OS3Handler::handle_publish_mecha_setting(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::publish_mecha_setting_5_t)) {
		DEBUG_PRINTLN("%u: Unexpected size of mecha setting, ignored", in_len);
		return;
	}
	auto msg = reinterpret_cast<const Sesame::publish_mecha_setting_5_t*>(in);
	client->setting.emplace<LockSetting>(msg->setting);
	setting_received = true;
	if (client->state != state_t::active && setting_received && status_received) {
		client->update_state(state_t::active);
	}
}

void
OS3Handler::handle_publish_mecha_status(const std::byte* in, size_t in_len) {
	DEBUG_PRINTLN("mecha: %s", util::bin2hex(in, in_len).c_str());
	if (client->model == Sesame::model_t::sesame_bot_2) {
		const auto* msg = reinterpret_cast<const Sesame::mecha_bot_2_status_t*>(in);
		client->sesame_status = {*msg, voltage_scale(client->model)};
	} else {
		if (in_len < sizeof(Sesame::publish_mecha_status_5_t)) {
			DEBUG_PRINTF("%u: Unexpected size of mecha status, ignored", in_len);
			return;
		}
		const auto* msg = reinterpret_cast<const Sesame::publish_mecha_status_5_t*>(in);
		client->sesame_status = {msg->status, voltage_scale(client->model)};
	}
	client->fire_status_callback();
	status_received = true;
	if (client->state != state_t::active && setting_received && status_received) {
		client->update_state(state_t::active);
	}
}

void
OS3Handler::handle_history(const std::byte* in, size_t in_len) {
	History history{};
	if (in_len < 1) {
		DEBUG_PRINTLN("%u: Unexpected size of history response, ignored", in_len);
		return;
	}
	history.result = static_cast<Sesame::result_code_t>(in[0]);
	if (history.result != Sesame::result_code_t::success || in_len < sizeof(Sesame::response_history_5_t)) {
		DEBUG_PRINTLN("%u: Empty history", history.result);
		client->fire_history_callback(history);
		return;
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
		auto tag_str = util::cleanup_tail_utf8({tag_data + 1, tag_len});
		history.tag_len = tag_str.length();
		*std::copy(std::begin(tag_str), std::end(tag_str), history.tag) = 0;
	} else {
		history.tag_len = 0;
		history.tag[0] = 0;
	}
	history.type = histtype;
	client->fire_history_callback(history);
}

}  // namespace libsesame3bt::core
