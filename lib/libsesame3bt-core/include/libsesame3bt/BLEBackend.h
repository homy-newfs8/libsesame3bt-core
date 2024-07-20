#pragma once
#include <cstddef>
#include <cstdint>

namespace libsesame3bt::core {

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
	/**
	 * @brief Disconnect BLE connection
	 *
	 */
	virtual void disconnect() = 0;
};

}  // namespace libsesame3bt::core
