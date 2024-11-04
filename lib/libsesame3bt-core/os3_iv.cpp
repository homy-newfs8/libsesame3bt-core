#include "os3_iv.h"

namespace libsesame3bt::core {

namespace {

constexpr size_t IV_COUNTER_SIZE = 5;

}

void
OS3IVHandler::update_c2p_iv(std::array<std::byte, 13>& c2p_iv) {
	c2p_count++;
	auto p = reinterpret_cast<const std::byte*>(&c2p_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(c2p_iv));
}

void
OS3IVHandler::update_p2c_iv(std::array<std::byte, 13>& p2c_iv) {
	p2c_count++;
	auto p = reinterpret_cast<const std::byte*>(&p2c_count);
	std::copy(p, p + IV_COUNTER_SIZE, std::begin(p2c_iv));
}

void
OS3IVHandler::init_ivs(const std::array<std::byte, Sesame::TOKEN_SIZE>&,
                       const std::byte (&nonce)[Sesame::TOKEN_SIZE],
                       std::array<std::byte, 13>& c2p_iv,
                       std::array<std::byte, 13>& p2c_iv) {
	p2c_count = c2p_count = 0;
	p2c_iv = {};
	std::copy(std::cbegin(nonce), std::cend(nonce), &p2c_iv[sizeof(p2c_count) + 1]);
	c2p_iv = {};
	std::copy(std::cbegin(nonce), std::cend(nonce), &c2p_iv[sizeof(c2p_count) + 1]);
}

}  // namespace libsesame3bt::core
