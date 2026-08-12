#pragma once
#include <cstddef>
#include <cstdint>

namespace libsesame3bt::core {

enum class result_t : uint8_t {
	success,
	invalid_state,
	invalid_packet,
	crypt_failure,
	transport_failure,
	auth_failure,
	operation_unsupported,
	invalid_argument
};

/**
 * @brief BLE communication backend interface
 *
 */
class SesameBLEBackend {
 public:
	/**
	 * @brief Send data to SESAME Tx characteristic
	 *
	 * @param data data to send
	 * @param size size of data
	 * @return true Success
	 * @return false Failure
	 */
	virtual bool write_to_tx(const uint8_t* data, size_t size) = 0;
};

class ServerBLEBackend {
 public:
	virtual bool write_to_central(uint16_t session_id, const uint8_t* data, size_t size) = 0;
};

}  // namespace libsesame3bt::core
