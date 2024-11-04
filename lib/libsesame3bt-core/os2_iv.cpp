#include "os2_iv.h"

namespace libsesame3bt::core {

namespace {

constexpr size_t AUTH_TAG_TRUNCATED_SIZE = 4;
constexpr size_t AES_KEY_SIZE = 16;
constexpr size_t IV_COUNTER_SIZE = 5;

}  // namespace

void
OS2IVHandler::update_c2p_iv(std::array<std::byte, 13>& c2p_iv) {
	c2p_count++;
	c2p_count &= 0x7fffffffffLL;
	c2p_count |= 0x8000000000LL;
	auto p = reinterpret_cast<const std::byte*>(&c2p_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(c2p_iv));
}

void
OS2IVHandler::update_p2c_iv(std::array<std::byte, 13>& p2c_iv) {
	p2c_count++;
	p2c_count &= 0x7fffffffffLL;
	auto p = reinterpret_cast<const std::byte*>(&p2c_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(p2c_iv));
}

void
OS2IVHandler::init_ivs(const std::array<std::byte, Sesame::TOKEN_SIZE>& local_nonce,
                       const std::byte (&remote_nonce)[Sesame::TOKEN_SIZE],
                       std::array<std::byte, 13>& c2p_iv,
                       std::array<std::byte, 13>& p2c_iv) {
	// iv = count[5] + local_tok + sesame_token
	p2c_iv = {};
	std::copy(std::cbegin(remote_nonce), std::cend(remote_nonce),
	          std::copy(local_nonce.cbegin(), local_nonce.cend(), &p2c_iv[IV_COUNTER_SIZE]));
	p2c_count = 0;

	std::copy(std::cbegin(p2c_iv), std::cend(p2c_iv), std::begin(c2p_iv));
	c2p_count = 0x8000000000;
	auto p = reinterpret_cast<const std::byte*>(&c2p_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(c2p_iv));
}

}  // namespace libsesame3bt::core
