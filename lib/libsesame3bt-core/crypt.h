#pragma once
#include <mbedtls/ccm.h>
#include <mbedtls/cipher.h>
#include <array>
#include <cstdint>
#include <variant>
#include "Sesame.h"
#include "api_wrapper.h"
#include "os2_iv.h"
#include "os3_iv.h"

namespace libsesame3bt::core {

class CmacAes128 {
 public:
	CmacAes128() {}
	bool set_key(const std::byte (&key)[16]);
	bool set_key(const std::array<std::byte, 16>& key) { return set_key(*reinterpret_cast<const std::byte(*)[16]>(key.data())); }
	bool update(const std::byte* data, size_t size);
	template <size_t N>
	bool update(const std::byte (&data)[N]) {
		return update(data, N);
	}
	template <size_t N>
	bool update(const std::array<std::byte, N> data) {
		return update(data.data(), N);
	}
	bool finish(std::byte (&cmac)[16]);
	bool finish(std::array<std::byte, 16>& cmac) { return finish(*reinterpret_cast<std::byte(*)[16]>(cmac.data())); }

 private:
	api_wrapper<mbedtls_cipher_context_t> ctx{mbedtls_cipher_init, mbedtls_cipher_free};
};

class CryptHandler {
 public:
	static constexpr size_t CMAC_TAG_SIZE = 4;
	template <typename T>
	CryptHandler(std::in_place_type_t<T> t, bool as_peripheral = false) : iv_handler(t), as_peripheral(as_peripheral) {}
	void update_enc_iv() {
		if (as_peripheral) {
			std::visit([this](auto& v) { v.update_p2c_iv(p2c_iv); }, iv_handler);
		} else {
			std::visit([this](auto& v) { v.update_c2p_iv(c2p_iv); }, iv_handler);
		}
	}
	void update_dec_iv() {
		if (as_peripheral) {
			std::visit([this](auto& v) { v.update_c2p_iv(c2p_iv); }, iv_handler);
		} else {
			std::visit([this](auto& v) { v.update_p2c_iv(p2c_iv); }, iv_handler);
		}
	}
	bool is_key_shared() const { return key_prepared; }
	bool decrypt(const std::byte* in, size_t in_size, std::byte* out, size_t out_size);
	bool encrypt(const std::byte* in, size_t in_size, std::byte* out, size_t out_size);
	bool set_session_key(const std::byte* key, size_t key_size);
	void init_endec_iv(const std::array<std::byte, Sesame::TOKEN_SIZE>& local_nonce,
	                   const std::byte (&remote_nonce)[Sesame::TOKEN_SIZE]) {
		std::visit([local_nonce, remote_nonce, this](auto& v) { v.init_ivs(local_nonce, remote_nonce, c2p_iv, p2c_iv); }, iv_handler);
	}
	void reset_session_key();

 private:
	std::variant<OS3IVHandler, OS2IVHandler> iv_handler;
	const bool as_peripheral;
	api_wrapper<mbedtls_ccm_context> ccm_ctx{mbedtls_ccm_init, mbedtls_ccm_free};
	static constexpr std::array<std::byte, 1> auth_add_data{};
	std::array<std::byte, 13> c2p_iv;
	std::array<std::byte, 13> p2c_iv;
	bool key_prepared = false;
};

}  // namespace libsesame3bt::core
