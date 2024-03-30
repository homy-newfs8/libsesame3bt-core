#include <mbedtls/base64.h>
#include "Sesame.h"
#include "libsesame3bt/ScannerCore.h"
#include "libsesame3bt/util.h"

#ifndef LIBSESAME3BTCORE_DEBUG
#define LIBSESAME3BTCORE_DEBUG 0
#endif
#include "debug.h"

namespace libsesame3bt::core {

namespace {

const uint8_t WIFI_MODULE_UUID_HEAD[]{0x00, 0x00, 0x00, 0x00, 0x05, 0x5a, 0xfd, 0x81, 0x00, 0x01};

}

/**
 * @brief
 * Convert BLE advertisement data and name to model, flags byte, UUID.
 * @param manu_data BLE manufacturer data prepended with 16-bit uuid
 * @param name BLE name data
 * @param[out] uuid_bin in big endian
 * @return std::tuple<Sesame::model_t model, std::byte flag_byte, bool success>
 */
std::tuple<Sesame::model_t, std::byte, bool>
parse_advertisement(std::string_view manu_data, std::string_view name, uint8_t (&uuid_bin)[16]) {
	if (manu_data.length() < 5 || manu_data[0] != 0x5a || manu_data[1] != 0x05) {
		DEBUG_PRINTF("Unexpected manufacturer data\n");
		return {Sesame::model_t::unknown, std::byte(0), false};
	}
	Sesame::model_t model = static_cast<Sesame::model_t>(manu_data[2]);
	std::byte flags = std::byte{manu_data[4]};
	if (model == Sesame::model_t::wifi_2) {
		if (manu_data.size() < 11) {
			return {model, flags, false};
		}
		std::copy(std::cbegin(manu_data) + 5, std::cbegin(manu_data) + 11,
		          std::copy(std::cbegin(WIFI_MODULE_UUID_HEAD), std::cend(WIFI_MODULE_UUID_HEAD), uuid_bin));
	} else {
		auto os = Sesame::get_os_ver(model);
		if (os == Sesame::os_ver_t::os2) {
			if (name.length() != 22) {
				DEBUG_PRINTF("%u: Unexpected name field length\n", name.length());
				return {model, flags, false};
			}
			uint8_t mod_name[22 + 2];
			std::copy(std::cbegin(name), std::cend(name), mod_name);
			mod_name[22] = mod_name[23] = '=';  // not nul terminated
			size_t idlen;
			int rc = mbedtls_base64_decode(uuid_bin, sizeof(uuid_bin), &idlen, mod_name, sizeof(mod_name));
			if (rc != 0 || idlen != sizeof(uuid_bin)) {
				return {model, flags, false};
			}
		} else if (os == Sesame::os_ver_t::os3) {
			if (manu_data.size() > 20) {
				std::copy(&manu_data[5], &manu_data[21], uuid_bin);
			} else {
				DEBUG_PRINTF("Unexpected manufacture data length");
				return {model, flags, false};
			}
		}
	}
	return {model, flags, true};
}

}  // namespace libsesame3bt::core
