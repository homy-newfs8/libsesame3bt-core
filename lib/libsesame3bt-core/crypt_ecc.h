#pragma once
#include <mbedtls/ecp.h>
#include "Sesame.h"
#include "crypt_random.h"

namespace libsesame3bt::core {
class SesameServerCoreImpl;
class Ecc {
	friend class SesameServerCoreImpl;

 public:
	static constexpr size_t PK_SIZE = 64;
	static constexpr size_t SK_SIZE = 32;
	Ecc() {}
	Ecc(const Ecc&) = delete;
	Ecc& operator=(const Ecc&) = delete;

	bool generate_keypair();
	bool load_key(const std::array<std::byte, 32>& privkey);
	bool export_pk(std::array<std::byte, PK_SIZE>& binary);
	bool ecdh(const api_wrapper<mbedtls_ecp_point>& remote_pk, api_wrapper<mbedtls_mpi>& shared_secret);
	bool derive_secret(const std::array<std::byte, PK_SIZE>& remote_pk, std::array<std::byte, Sesame::SECRET_SIZE>& shared_secret);
	bool convert_sk_to_binary(const api_wrapper<mbedtls_mpi>& sk, std::array<std::byte, SK_SIZE>& binary);
	bool convert_binary_to_pk(const std::array<std::byte, PK_SIZE>& binary, api_wrapper<mbedtls_ecp_point>& pk);

	static bool initialized() { return static_initialized; }

 private:
	static bool static_initialized;
	static inline api_wrapper<mbedtls_ecp_group> ec_grp{mbedtls_ecp_group_init, mbedtls_ecp_group_free};
	bool have_keypair = false;
	api_wrapper<mbedtls_ecp_point> pk{mbedtls_ecp_point_init, mbedtls_ecp_point_free};
	api_wrapper<mbedtls_mpi> sk{mbedtls_mpi_init, mbedtls_mpi_free};
};

}  // namespace libsesame3bt::core
