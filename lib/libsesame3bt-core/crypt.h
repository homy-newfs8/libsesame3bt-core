#pragma once
#include <mbedtls/ccm.h>
#include <array>
#include <cstdint>
#include <variant>
#include "Sesame.h"
#include "api_wrapper.h"
#include "os2_crypt.h"
#include "os3_crypt.h"

namespace libsesame3bt::core {

class CryptHandler {
 public:
	static constexpr size_t CMAC_TAG_SIZE = 4;
	template <typename T>
	CryptHandler(std::in_place_type_t<T> t) : handler(t) {}
	bool init() {
		return std::visit([](auto& v) { return v.init(); }, handler);
	}
	void update_enc_iv() {
		std::visit([this](auto& v) { v.update_enc_iv(enc_iv); }, handler);
	}
	void update_dec_iv() {
		std::visit([this](auto& v) { v.update_dec_iv(dec_iv); }, handler);
	}
	bool is_key_shared() const { return key_prepared; }
	bool decrypt(const std::byte* in, size_t in_size, std::byte* out, size_t out_size);
	bool encrypt(const std::byte* in, size_t in_size, std::byte* out, size_t out_size);
	bool set_session_key(const std::byte* key, size_t key_size);
	void init_endec_iv(const std::array<std::byte, Sesame::TOKEN_SIZE>& local_nonce,
	                   const std::byte (&remote_nonce)[Sesame::TOKEN_SIZE]) {
		std::visit([local_nonce, remote_nonce, this](auto& v) { v.init_endec_iv(local_nonce, remote_nonce, enc_iv, dec_iv); }, handler);
	}
	void reset_session_key();

 private:
	std::variant<OS3CryptHandler, OS2CryptHandler> handler;
	api_wrapper<mbedtls_ccm_context> ccm_ctx{mbedtls_ccm_init, mbedtls_ccm_free};
	static constexpr std::array<std::byte, 1> auth_add_data{};
	std::array<std::byte, 13> enc_iv;
	std::array<std::byte, 13> dec_iv;
	bool key_prepared = false;
};

}  // namespace libsesame3bt::core
