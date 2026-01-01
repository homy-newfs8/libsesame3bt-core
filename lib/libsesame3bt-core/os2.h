#pragma once
#include <array>
#include <cstdint>
#include <string_view>
#include "Sesame.h"
#include "crypt.h"
#include "crypt_ecc.h"
#include "transport.h"

namespace libsesame3bt::core {

class SesameClientCoreImpl;

class OS2Handler {
 public:
	OS2Handler(SesameClientCoreImpl* client, SesameBLETransport& transport, CryptHandler& crypt)
	    : client(client), transport(transport), crypt(crypt) {}
	OS2Handler(const OS2Handler&) = delete;
	OS2Handler& operator=(const OS2Handler&) = delete;
	bool init() { return Ecc::initialized(); }
	bool set_keys(std::string_view pk_str, std::string_view secret_str);
	bool set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
	              const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key);
	bool send_command(Sesame::op_code_t op_code,
	                  Sesame::item_code_t item_code,
	                  const std::byte* data,
	                  size_t data_size,
	                  bool is_crypted);

	void handle_publish_initial(const std::byte* in, size_t in_len);
	void handle_response_login(const std::byte* in, size_t in_len);
	void handle_publish_mecha_setting(const std::byte* in, size_t in_len);
	void handle_publish_mecha_status(const std::byte* in, size_t in_len);
	void handle_response_mecha_status(const std::byte* in, size_t in_len) { handle_publish_mecha_status(in + 2, in_len - 2); };
	void handle_history(const std::byte* in, size_t in_len);
	size_t get_max_history_tag_size() const { return MAX_HISTORY_TAG_SIZE; }
	size_t get_cmd_tag_size(size_t tag_len) const { return MAX_HISTORY_TAG_SIZE + 1; }
	static constexpr size_t MAX_HISTORY_TAG_SIZE = 21;

 private:
	SesameClientCoreImpl* client;
	SesameBLETransport& transport;
	CryptHandler& crypt;
	Ecc ecc;
	api_wrapper<mbedtls_ecp_point> sesame_pk{mbedtls_ecp_point_init, mbedtls_ecp_point_free};
	std::array<std::byte, Sesame::SECRET_SIZE> sesame_secret{};
	long long enc_count = 0;
	long long dec_count = 0;

	static constexpr std::array<std::byte, 2> sesame_ki{};
	static constexpr size_t AES_BLOCK_SIZE = 16;

	bool generate_session_key(const std::array<std::byte, Sesame::TOKEN_SIZE>& local_tok,
	                          const std::byte (&sesame_token)[Sesame::TOKEN_SIZE],
	                          std::array<std::byte, Sesame::PK_SIZE>& pk);
	bool ecdh(std::array<std::byte, Ecc::SK_SIZE>& out);
	bool create_key_pair(std::array<std::byte, Sesame::PK_SIZE>& pk);
	bool generate_tag_response(const std::array<std::byte, Sesame::PK_SIZE>& pk,
	                           const std::array<std::byte, Sesame::TOKEN_SIZE>& local_token,
	                           const std::byte (&sesame_token)[Sesame::TOKEN_SIZE],
	                           std::array<std::byte, AES_BLOCK_SIZE>& tag_response);
	void update_sesame_status(const Sesame::mecha_status_t& mecha_status);
};

}  // namespace libsesame3bt::core
