#pragma once
#include <array>
#include <cstddef>
#include "Sesame.h"

namespace libsesame3bt::core {

class OS2IVHandler {
 public:
	OS2IVHandler() {}
	void update_c2p_iv(std::array<std::byte, 13>& c2p_iv);
	void update_p2c_iv(std::array<std::byte, 13>& p2c_iv);
	void init_ivs(const std::array<std::byte, Sesame::TOKEN_SIZE>& local_nonce,
	              const std::byte (&remote_nonce)[Sesame::TOKEN_SIZE],
	              std::array<std::byte, 13>& c2p_iv,
	              std::array<std::byte, 13>& p2c_iv);

 private:
	long long c2p_count = 0;
	long long p2c_count = 0;
};

}  // namespace libsesame3bt::core
