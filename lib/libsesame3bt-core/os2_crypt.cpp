#include "os2_crypt.h"

namespace libsesame3bt::core {

namespace {

constexpr size_t AUTH_TAG_TRUNCATED_SIZE = 4;
constexpr size_t AES_KEY_SIZE = 16;
constexpr size_t IV_COUNTER_SIZE = 5;

}  // namespace

void
OS2CryptHandler::update_enc_iv(std::array<std::byte, 13>& enc_iv) {
	enc_count++;
	enc_count &= 0x7fffffffffLL;
	enc_count |= 0x8000000000LL;
	auto p = reinterpret_cast<const std::byte*>(&enc_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(enc_iv));
}

void
OS2CryptHandler::update_dec_iv(std::array<std::byte, 13>& dec_iv) {
	dec_count++;
	dec_count &= 0x7fffffffffLL;
	auto p = reinterpret_cast<const std::byte*>(&dec_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(dec_iv));
}

void
OS2CryptHandler::init_endec_iv(const std::array<std::byte, Sesame::TOKEN_SIZE>& local_nonce,
                               const std::byte (&remote_nonce)[Sesame::TOKEN_SIZE],
                               std::array<std::byte, 13>& enc_iv,
                               std::array<std::byte, 13>& dec_iv) {
	// iv = count[5] + local_tok + sesame_token
	dec_iv = {};
	std::copy(std::cbegin(remote_nonce), std::cend(remote_nonce),
	          std::copy(local_nonce.cbegin(), local_nonce.cend(), &dec_iv[IV_COUNTER_SIZE]));
	dec_count = 0;

	std::copy(std::cbegin(dec_iv), std::cend(dec_iv), std::begin(enc_iv));
	enc_count = 0x8000000000;
	auto p = reinterpret_cast<const std::byte*>(&enc_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(enc_iv));
}

}  // namespace libsesame3bt::core
