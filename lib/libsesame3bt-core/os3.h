#pragma once
#include <array>
#include <cstdint>
#include <string_view>
#include "Sesame.h"
#include "crypt.h"
#include "transport.h"

namespace libsesame3bt::core {

class SesameClientCoreImpl;

class OS3Handler {
 public:
	OS3Handler(SesameClientCoreImpl* client, SesameBLETransport& transport, CryptHandler& crypt)
	    : client(client), transport(transport), crypt(crypt) {}
	OS3Handler(const OS3Handler&) = delete;
	OS3Handler& operator=(const OS3Handler&) = delete;
	result_t init() { return result_t::success; }
	result_t set_keys(std::string_view pk_str, std::string_view secret_str);
	result_t set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
	                  const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key);
	result_t send_command(Sesame::op_code_t op_code,
	                      Sesame::item_code_t item_code,
	                      const std::byte* data,
	                      size_t data_size,
	                      bool is_crypted);

	result_t handle_publish_initial(const std::byte* in, size_t in_len);
	result_t handle_response_login(const std::byte* in, size_t in_len);
	result_t handle_publish_mecha_setting(const std::byte* in, size_t in_len);
	result_t handle_publish_mecha_status(const std::byte* in, size_t in_len);
	result_t handle_response_mecha_status(const std::byte* in, size_t in_len) {
		return handle_publish_mecha_status(in + 1, in_len - 1);
	};
	result_t handle_history(const std::byte* in, size_t in_len);
	size_t get_max_history_tag_size() const { return MAX_HISTORY_TAG_SIZE; }
	size_t get_cmd_tag_size(size_t tag_len) const { return tag_len + 1; }
	static constexpr size_t MAX_HISTORY_TAG_SIZE = 29;

 private:
	SesameClientCoreImpl* client;
	SesameBLETransport& transport;
	CryptHandler& crypt;
	std::array<std::byte, Sesame::SECRET_SIZE> sesame_secret{};
	long long enc_count = 0;
	long long dec_count = 0;
};

}  // namespace libsesame3bt::core
