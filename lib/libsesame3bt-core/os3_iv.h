#pragma once
#include <array>
#include <cstddef>
#include "Sesame.h"

namespace libsesame3bt::core {

class OS3IVHandler {
 public:
	OS3IVHandler() {}
	void update_enc_iv(std::array<std::byte, 13>& enc_iv);
	void update_dec_iv(std::array<std::byte, 13>& dec_iv);
	void init_endec_iv(const std::array<std::byte, Sesame::TOKEN_SIZE>&,
	                   const std::byte (&remote_nonce)[Sesame::TOKEN_SIZE],
	                   std::array<std::byte, 13>& enc_iv,
	                   std::array<std::byte, 13>& dec_iv);

 private:
	long long enc_count = 0;
	long long dec_count = 0;
};

}  // namespace libsesame3bt::core
