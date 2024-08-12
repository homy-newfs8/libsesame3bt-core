#include "crypt.h"
#include <mbedtls/cmac.h>
#include <cstddef>
#include "debug.h"
#include "libsesame3bt/util.h"

namespace libsesame3bt::core {

using util::to_byte;
using util::to_cptr;
using util::to_ptr;

bool
CryptHandler::decrypt(const std::byte* in, size_t in_len, std::byte* out, size_t out_size) {
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
	update_dec_iv();
	return true;
}

bool
CryptHandler::encrypt(const std::byte* in, size_t in_len, std::byte* out, size_t out_size) {
	if (out_size < in_len + CMAC_TAG_SIZE) {
		return false;
	}
	int rc;
	if ((rc = mbedtls_ccm_encrypt_and_tag(&ccm_ctx, in_len, to_cptr(enc_iv), enc_iv.size(), to_cptr(auth_add_data),
	                                      auth_add_data.size(), to_cptr(in), to_ptr(out), to_ptr(&out[in_len]), CMAC_TAG_SIZE)) !=
	    0) {
		DEBUG_PRINTF("%d: encrypt_and_tag failed\n", rc);
	}
	update_enc_iv();
	return true;
}

bool
CryptHandler::set_session_key(const std::byte* key,
                              size_t key_size,
                              const std::array<std::byte, Sesame::TOKEN_SIZE>& local_nonce,
                              const std::byte (&remote_nonce)[Sesame::TOKEN_SIZE]) {
	if (int mbrc = mbedtls_ccm_setkey(&ccm_ctx, mbedtls_cipher_id_t::MBEDTLS_CIPHER_ID_AES, to_cptr(key), key_size * 8); mbrc != 0) {
		DEBUG_PRINTF("%d: ccm_setkey failed\n", mbrc);
		return false;
	}
	std::copy(key, key + auth_code.size(), std::begin(auth_code));
	std::visit([local_nonce, remote_nonce, this](auto& v) { v.init_endec_iv(local_nonce, remote_nonce, enc_iv, dec_iv); },
	           iv_handler);
	key_prepared = true;
	return true;
}

void
CryptHandler::reset_session_key() {
	ccm_ctx.reset();
	key_prepared = false;
}

bool
CryptHandler::verify_auth_code(const std::byte* code) const {
	return std::equal(std::cbegin(auth_code), std::cend(auth_code), code);
}

bool
CmacAes128::set_key(const std::byte (&key)[16]) {
	int mbrc;
	if ((mbrc = mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_ECB))) != 0) {
		DEBUG_PRINTF("%d: cipher setup failed\n", mbrc);
		return false;
	}
	if ((mbrc = mbedtls_cipher_cmac_starts(&ctx, to_cptr(key), sizeof(key) * 8)) != 0) {
		DEBUG_PRINTF("%d: cmac start failed\n", mbrc);
		return false;
	}
	return true;
}

bool
CmacAes128::update(const std::byte* data, size_t size) {
	if (int mbrc = mbedtls_cipher_cmac_update(&ctx, to_cptr(data), size); mbrc != 0) {
		DEBUG_PRINTF("%d: cmac update failed\n", mbrc);
		return false;
	}
	return true;
}

bool
CmacAes128::finish(std::byte (&cmac)[16]) {
	if (int mbrc = mbedtls_cipher_cmac_finish(&ctx, to_ptr(cmac)); mbrc != 0) {
		DEBUG_PRINTF("%d: cmac_finish failed\n", mbrc);
		return false;
	}
	return true;
}

}  // namespace libsesame3bt::core
