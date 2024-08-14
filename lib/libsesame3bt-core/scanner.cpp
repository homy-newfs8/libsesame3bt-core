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
 * @brief Create data for BLE advertisement.
 *
 * @param model Sesame model
 * @param flag flag value
 * @param uuid 128bit uuid (big endian)
 * @return tuple of "manufacturer data" and "local name"
 */
std::tuple<std::string, std::string>
create_advertisement_data_os3(Sesame::model_t model, std::byte flag, const uint8_t (&uuid)[16]) {
	DEBUG_PRINTLN("c uuid=%s", util::bin2hex(uuid).c_str());
	std::string manu;
	manu.push_back(static_cast<char>(Sesame::COMPANY_ID & 0xff));
	manu.push_back(static_cast<char>(Sesame::COMPANY_ID >> 8));
	manu.push_back(static_cast<char>(model));
	manu.push_back(0);
	manu.push_back(static_cast<char>(flag));
	manu.append(std::cbegin(uuid), std::cend(uuid));

	uint8_t b64[25];
	size_t out_len;
	if (int mbrc = mbedtls_base64_encode(b64, sizeof(b64), &out_len, uuid, sizeof(uuid)); mbrc != 0) {
		DEBUG_PRINTLN("This cannot be happened...");
	}
	std::string name{reinterpret_cast<const char*>(b64), 22};
	return std::make_tuple(manu, name);
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
		DEBUG_PRINTF("Unexpected manufacturer data, len=%u\n", manu_data.length());
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
	DEBUG_PRINTLN("manu data=%s", util::bin2hex(manu_data).c_str());
	return {model, flags, true};
}

}  // namespace libsesame3bt::core
