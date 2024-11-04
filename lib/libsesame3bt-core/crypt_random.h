#pragma once
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <array>
#include <cstddef>
#include "api_wrapper.h"

namespace libsesame3bt::core {

class Ecc;

class Random {
	friend class Ecc;

 public:
	static bool get_random(std::byte* out, size_t size);
	template <size_t N>
	static bool get_random(std::byte (&out)[N]) {
		return get_random(out, N);
	};
	template <size_t N>
	static bool get_random(std::array<std::byte, N> out) {
		return get_random(out.data(), out.size());
	}

 private:
	static bool static_initialized;
	static inline api_wrapper<mbedtls_ctr_drbg_context> rng_ctx{mbedtls_ctr_drbg_init, mbedtls_ctr_drbg_free};
	static inline api_wrapper<mbedtls_entropy_context> ent_ctx{mbedtls_entropy_init, mbedtls_entropy_free};
};

}  // namespace libsesame3bt::core
