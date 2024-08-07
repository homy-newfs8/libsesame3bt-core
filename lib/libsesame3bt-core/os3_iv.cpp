#include "os3_iv.h"

namespace libsesame3bt::core {

namespace {

constexpr size_t IV_COUNTER_SIZE = 5;

}

void
OS3IVHandler::update_enc_iv(std::array<std::byte, 13>& enc_iv) {
	enc_count++;
	auto p = reinterpret_cast<const std::byte*>(&enc_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(enc_iv));
}

void
OS3IVHandler::update_dec_iv(std::array<std::byte, 13>& dec_iv) {
	dec_count++;
	auto p = reinterpret_cast<const std::byte*>(&dec_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(dec_iv));
}

void
OS3IVHandler::init_endec_iv(const std::array<std::byte, Sesame::TOKEN_SIZE>&,
                            const std::byte (&nonce)[Sesame::TOKEN_SIZE],
                            std::array<std::byte, 13>& enc_iv,
                            std::array<std::byte, 13>& dec_iv) {
	dec_count = enc_count = 0;
	dec_iv = {};
	std::copy(std::cbegin(nonce), std::cend(nonce), &dec_iv[sizeof(dec_count) + 1]);
	enc_iv = {};
	std::copy(std::cbegin(nonce), std::cend(nonce), &enc_iv[sizeof(enc_count) + 1]);
}

}  // namespace libsesame3bt::core
