#include "crypt_ecc.h"
#include <mbedtls/ecdh.h>
#include "Sesame.h"
#include "crypt_random.h"
#include "debug.h"
#include "libsesame3bt/util.h"

namespace libsesame3bt::core {

using util::to_cptr;
using util::to_ptr;

bool Ecc::static_initialized = [] {
	if (mbedtls_ecp_group_load(&ec_grp, mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1) != 0) {
		DEBUG_PRINTLN("ecp_group_load failed");
		return false;
	}
	return Random::static_initialized;
}();

bool
Ecc::generate_keypair() {
	if (int mbrc = mbedtls_ecdh_gen_public(&ec_grp, &sk, &pk, mbedtls_ctr_drbg_random, &Random::rng_ctx); mbrc != 0) {
		DEBUG_PRINTF("%d: ecdh_gen_public failed\n", mbrc);
		return false;
	}
	have_keypair = true;
	return true;
}

bool
Ecc::export_pk(std::array<std::byte, PK_SIZE>& binary) {
	if (!have_keypair) {
		DEBUG_PRINTLN("Keypair not generated");
		return false;
	}
	std::array<std::byte, 1 + PK_SIZE> temp;
	size_t olen;
	int mbrc;
	if ((mbrc = mbedtls_ecp_point_write_binary(&ec_grp, &pk, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, to_ptr(temp.data()), temp.size())) !=
	    0) {
		DEBUG_PRINTF("%d: ecp_point_write_binary failed\n", mbrc);
		return false;
	}
	if (olen != temp.size()) {
		DEBUG_PRINTLN("write_binary pk length not match");
		return false;
	}
	std::copy(temp.data() + 1, temp.data() + temp.size(), binary.data());
	return true;
}

bool
Ecc::derive_secret(const std::array<std::byte, PK_SIZE>& remote_pk_bin, std::array<std::byte, Sesame::SECRET_SIZE>& sesame_secret) {
	api_wrapper<mbedtls_ecp_point> remote_pk{mbedtls_ecp_point_init, mbedtls_ecp_point_free};
	if (!convert_binary_to_pk(remote_pk_bin, remote_pk)) {
		return false;
	}
	api_wrapper<mbedtls_mpi> secret{mbedtls_mpi_init, mbedtls_mpi_free};
	if (!ecdh(remote_pk, secret)) {
		return false;
	}
	std::array<std::byte, SK_SIZE> secret_bin;
	if (!convert_sk_to_binary(secret, secret_bin)) {
		return false;
	}
	std::copy(std::cbegin(secret_bin), std::cbegin(secret_bin) + sizeof(sesame_secret), std::begin(sesame_secret));

	return true;
}

bool
Ecc::ecdh(const api_wrapper<mbedtls_ecp_point>& remote_pk, api_wrapper<mbedtls_mpi>& shared_secret) {
	if (int mbrc = mbedtls_ecdh_compute_shared(&ec_grp, &shared_secret, &remote_pk, &sk, mbedtls_ctr_drbg_random, &Random::rng_ctx);
	    mbrc != 0) {
		DEBUG_PRINTF("%d: ecdh_compute_shared failed\n", mbrc);
		return false;
	}
	return true;
}

bool
Ecc::convert_sk_to_binary(const api_wrapper<mbedtls_mpi>& sk, std::array<std::byte, SK_SIZE>& binary) {
	if (int mbrc = mbedtls_mpi_write_binary(&sk, to_ptr(binary), binary.size()); mbrc != 0) {
		DEBUG_PRINTF("%d: mpi_write_binary failed\n", mbrc);
		return false;
	}
	return true;
}

bool
Ecc::convert_binary_to_pk(const std::array<std::byte, PK_SIZE>& binary, api_wrapper<mbedtls_ecp_point>& pk) {
	std::array<std::byte, 1 + PK_SIZE> bin_pk;  // 1 for indicator (SEC1 2.3.4)
	bin_pk[0] = std::byte{4};                   // uncompressed point indicator
	std::copy(std::cbegin(binary), std::cend(binary), &bin_pk[1]);
	int mbrc;
	if ((mbrc = mbedtls_ecp_point_read_binary(&ec_grp, &pk, to_cptr(bin_pk), bin_pk.size())) != 0) {
		DEBUG_PRINTF("%d: ecp_point_read_binary failed", mbrc);
		return false;
	}
	if ((mbrc = mbedtls_ecp_check_pubkey(&ec_grp, &pk)) != 0) {
		DEBUG_PRINTF("%d: ecp_check_pubkey failed", mbrc);
		return false;
	}
	return true;
}

bool
Ecc::load_key(const std::array<std::byte, 32>& privkey) {
	if (int mbrc = mbedtls_mpi_read_binary(&sk, to_cptr(privkey), privkey.size()); mbrc != 0) {
		DEBUG_PRINTLN("%d: Failed to mpi read bibary", mbrc);
		return false;
	}
	if (int mbrc = mbedtls_ecp_check_privkey(&ec_grp, &sk); mbrc != 0) {
		DEBUG_PRINTLN("%d: Invalid secret key", mbrc);
		return false;
	}
	if (int mbrc = mbedtls_ecp_mul(&ec_grp, &pk, &sk, &ec_grp->G, mbedtls_ctr_drbg_random, &Random::rng_ctx); mbrc != 0) {
		DEBUG_PRINTLN("%d: Failed to derive public key", mbrc);
		return false;
	}
	have_keypair = true;
	return true;
}

}  // namespace libsesame3bt::core
