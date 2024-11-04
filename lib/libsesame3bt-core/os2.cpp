#include "os2.h"
#include "ClientCoreImpl.h"
#include "Sesame.h"
#include "libsesame3bt/util.h"

#ifndef LIBSESAME3BTCORE_DEBUG
#define LIBSESAME3BTCORE_DEBUG 0
#endif
#include "debug.h"

namespace libsesame3bt::core {

namespace {

constexpr size_t AUTH_TAG_TRUNCATED_SIZE = 4;
constexpr size_t AES_KEY_SIZE = 16;
constexpr size_t IV_COUNTER_SIZE = 5;

}  // namespace

using util::to_byte;
using util::to_cptr;
using util::to_ptr;

bool
OS2Handler::set_keys(std::string_view pk_str, std::string_view secret_str) {
	std::array<std::byte, Sesame::SECRET_SIZE> secret;
	if (!util::hex2bin(secret_str, secret)) {
		DEBUG_PRINTLN("secret_str invalid format");
		return false;
	}
	std::array<std::byte, Sesame::PK_SIZE> pk;
	if (!util::hex2bin(pk_str, pk)) {
		DEBUG_PRINTLN("pk_str invalid format");
		return false;
	}
	return set_keys(pk, secret);

	return false;
}

bool
OS2Handler::set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
                     const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key) {
	if (!ecc.convert_binary_to_pk(public_key, sesame_pk)) {
		return false;
	}
	std::copy(std::cbegin(secret_key), std::cend(secret_key), std::begin(sesame_secret));
	client->is_key_set = true;

	return true;
}

bool
OS2Handler::send_command(Sesame::op_code_t op_code,
                         Sesame::item_code_t item_code,
                         const std::byte* data,
                         size_t data_size,
                         bool is_crypted) {
	return transport.send_notify(op_code, item_code, data, data_size, is_crypted, crypt);
}

void
OS2Handler::handle_publish_initial(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::publish_initial_t)) {
		DEBUG_PRINTF("%u: short response initial data\n", in_len);
		client->disconnect();
		return;
	}
	crypt.reset_session_key();
	auto msg = reinterpret_cast<const Sesame::publish_initial_t*>(in);

	std::array<std::byte, Sesame::TOKEN_SIZE> local_tok;
	if (!Random::get_random(local_tok)) {
		client->disconnect();
		return;
	}

	std::array<std::byte, Sesame::PK_SIZE> bpk;
	if (!generate_session_key(local_tok, msg->token, bpk)) {
		client->disconnect();
		return;
	}
	std::array<std::byte, AES_BLOCK_SIZE> tag_response;
	if (!generate_tag_response(bpk, local_tok, msg->token, tag_response)) {
		client->disconnect();
		return;
	}

	constexpr size_t resp_size = sesame_ki.size() + Sesame::PK_SIZE + local_tok.size() + AUTH_TAG_TRUNCATED_SIZE;
	std::array<std::byte, resp_size> resp;

	// resp = sesame_ki + pk + local_tok + tag_response[:4]
	std::copy(tag_response.cbegin(), tag_response.cbegin() + AUTH_TAG_TRUNCATED_SIZE,
	          std::copy(local_tok.cbegin(), local_tok.cend(),
	                    std::copy(bpk.begin(), bpk.end(), std::copy(sesame_ki.cbegin(), sesame_ki.cend(), resp.begin()))));

	if (send_command(Sesame::op_code_t::sync, Sesame::item_code_t::login, resp.data(), resp.size(), false)) {
		client->update_state(state_t::authenticating);
	} else {
		client->disconnect();
	}
}

void
OS2Handler::handle_response_login(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::response_login_t)) {
		DEBUG_PRINTLN("short response login message");
		client->disconnect();
		return;
	}
	auto msg = reinterpret_cast<const Sesame::response_login_t*>(in);
	if (msg->result != Sesame::result_code_t::success) {
		DEBUG_PRINTF("%u: login response was not success\n", static_cast<uint8_t>(msg->result));
		client->disconnect();
		return;
	}
	if (client->model == Sesame::model_t::sesame_bot) {
		client->setting.emplace<BotSetting>(msg->mecha_setting);
	} else {
		client->setting.emplace<LockSetting>(msg->mecha_setting);
	}
	update_sesame_status(msg->mecha_status);
	client->update_state(state_t::active);
	client->fire_status_callback();
}

void
OS2Handler::handle_history(const std::byte* in, size_t in_len) {
	History history{};
	if (in_len < 2) {
		DEBUG_PRINTF("%u: Unexpected size of history, ignored\n", in_len);
		client->fire_history_callback(history);
		return;
	}
	if (static_cast<Sesame::result_code_t>(in[1]) != Sesame::result_code_t::success) {
		DEBUG_PRINTF("%u: Failure response to request history\n", static_cast<uint8_t>(in[1]));
		client->fire_history_callback(history);
		return;
	}
	if (in_len < sizeof(Sesame::response_history_t)) {
		DEBUG_PRINTF("%u: Unexpected size of history, ignored\n", in_len);
		client->fire_history_callback(history);
		return;
	}
	const auto* hist = reinterpret_cast<const Sesame::response_history_t*>(in);
	history.time = static_cast<time_t>(hist->timestamp / 1000);
	auto histtype = hist->type;
	if (histtype > Sesame::history_type_t::web_unlock && histtype != Sesame::history_type_t::drive_clicked) {
		histtype = Sesame::history_type_t::none;
	}
	constexpr size_t SKIP_SIZE = 18;
	if (in_len > sizeof(Sesame::response_history_t) + SKIP_SIZE) {
		const auto* tag_data = reinterpret_cast<const char*>(in + sizeof(Sesame::response_history_t) + SKIP_SIZE);
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

void
OS2Handler::update_sesame_status(const Sesame::mecha_status_t& mecha_status) {
	if (client->model == Sesame::model_t::sesame_bot) {
		client->sesame_status = {mecha_status.bot, battery_voltage(client->model, mecha_status.bot.battery)};
	} else {
		client->sesame_status = {mecha_status.lock, battery_voltage(client->model, mecha_status.lock.battery),
		                         voltage_scale(client->model)};
	}
}
void
OS2Handler::handle_publish_mecha_setting(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::publish_mecha_setting_t)) {
		DEBUG_PRINTF("%u: Unexpected size of mecha setting, ignored\n", in_len);
		return;
	}
	auto msg = reinterpret_cast<const Sesame::publish_mecha_setting_t*>(in);
	if (client->model == Sesame::model_t::sesame_bot) {
		client->setting.emplace<BotSetting>(msg->setting);
	} else {
		client->setting.emplace<LockSetting>(msg->setting);
	}
}

void
OS2Handler::handle_publish_mecha_status(const std::byte* in, size_t in_len) {
	if (in_len < sizeof(Sesame::publish_mecha_status_t)) {
		DEBUG_PRINTF("%u: Unexpected size of mecha status, ignored\n", in_len);
		return;
	}
	auto msg = reinterpret_cast<const Sesame::publish_mecha_status_t*>(in);
	update_sesame_status(msg->status);
	client->fire_status_callback();
}

bool
OS2Handler::generate_session_key(const std::array<std::byte, Sesame::TOKEN_SIZE>& local_tok,
                                 const std::byte (&sesame_token)[Sesame::TOKEN_SIZE],
                                 std::array<std::byte, Sesame::PK_SIZE>& pk) {
	if (!create_key_pair(pk)) {
		return false;
	}
	std::array<std::byte, Ecc::SK_SIZE> ssec;
	if (!ecdh(ssec)) {
		return false;
	}

	CmacAes128 cmac;
	std::array<std::byte, 16> session_key;
	if (!cmac.set_key(*reinterpret_cast<const std::byte(*)[AES_KEY_SIZE]>(ssec.data())) || !cmac.update(local_tok) ||
	    !cmac.update(sesame_token) || !cmac.finish(session_key)) {
		return false;
	}
	if (!crypt.set_session_key(session_key.data(), session_key.size(), local_tok, sesame_token)) {
		return false;
	}
	return true;
}

bool
OS2Handler::create_key_pair(std::array<std::byte, Sesame::PK_SIZE>& bin_pk) {
	if (!ecc.generate_keypair()) {
		return false;
	}
	if (!ecc.export_pk(bin_pk)) {
		return false;
	}
	return true;
}

float
OS2Handler::battery_voltage(Sesame::model_t model, int16_t battery) {
	switch (model) {
		case Sesame::model_t::sesame_3:
		case Sesame::model_t::sesame_4:
			return battery * 7.2f / 1023;
		case Sesame::model_t::sesame_bike:
		case Sesame::model_t::sesame_bot:
			return battery * 3.6f / 1023;
		default:
			return 0.0f;
	}
}

bool
OS2Handler::ecdh(std::array<std::byte, Ecc::SK_SIZE>& out) {
	api_wrapper<mbedtls_mpi> shared_secret(mbedtls_mpi_init, mbedtls_mpi_free);
	if (!ecc.ecdh(sesame_pk, shared_secret)) {
		return false;
	}
	if (!ecc.convert_sk_to_binary(shared_secret, out)) {
		return false;
	}
	return true;
}

bool
OS2Handler::generate_tag_response(const std::array<std::byte, Sesame::PK_SIZE>& bpk,
                                  const std::array<std::byte, Sesame::TOKEN_SIZE>& local_tok,
                                  const std::byte (&sesame_token)[4],
                                  std::array<std::byte, AES_BLOCK_SIZE>& tag_response) {
	CmacAes128 cmac;
	if (!cmac.set_key(sesame_secret) || !cmac.update(sesame_ki) || !cmac.update(bpk) || !cmac.update(local_tok) ||
	    !cmac.update(sesame_token) || !cmac.finish(tag_response)) {
		return false;
	}
	return true;
}

}  // namespace libsesame3bt::core
