#include "crypt_random.h"
#include "debug.h"
#include "libsesame3bt/util.h"

namespace libsesame3bt::core {

using util::to_ptr;

bool Random::static_initialized = [] {
	if (mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &ent_ctx, nullptr, 0) != 0) {
		DEBUG_PRINTLN("drbg_seed failed");
		return false;
	}
	return true;
}();

bool
Random::get_random(std::byte* out, size_t size) {
	int mbrc;
	if ((mbrc = mbedtls_ctr_drbg_random(&rng_ctx, to_ptr(out), size)) != 0) {
		DEBUG_PRINTF("%d: drbg_random failed\n", mbrc);
		return false;
	}
	return true;
}

}  // namespace libsesame3bt::core
