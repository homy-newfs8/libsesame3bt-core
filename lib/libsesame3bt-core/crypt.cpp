#include "crypt.h"
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
CryptHandler::set_session_key(const std::byte* key, size_t key_size) {
	if (int mbrc = mbedtls_ccm_setkey(&ccm_ctx, mbedtls_cipher_id_t::MBEDTLS_CIPHER_ID_AES, to_cptr(key), key_size * 8); mbrc != 0) {
		DEBUG_PRINTF("%d: ccm_setkey failed\n", mbrc);
		return false;
	}
	key_prepared = true;
	return true;
}

void
CryptHandler::reset_session_key() {
	ccm_ctx.reset();
	key_prepared = false;
}

}  // namespace libsesame3bt::core
