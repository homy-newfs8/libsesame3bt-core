#pragma once
#include <cstddef>
#include "crypt.h"
#include "libsesame3bt/BLEBackend.h"

namespace libsesame3bt::core {

enum packet_kind_t { not_finished = 0, plain = 1, encrypted = 2 };  // do not use enum class to avoid warning in structure below.
union __attribute__((packed)) packet_header_t {
	struct __attribute__((packed)) {
		bool is_start : 1;
		packet_kind_t kind : 2;
		std::byte unused : 5;
	};
	std::byte value;
};

class SesameBLEBuffer {
	friend class SesameBLETransport;

 public:
	static constexpr size_t MAX_RECV = 128;

	SesameBLEBuffer() { reset(); }
	void reset() {
		recv_size = 0;
		skipping = false;
	}

 private:
	std::array<std::byte, MAX_RECV> recv_buffer{};
	size_t recv_size;
	bool skipping;
};

class SesameBLETransport {
 public:
	enum class decode_result_t { skipping, received, require_more, dropped };
	SesameBLETransport(SesameBLEBackend& backend) : backend(backend) {}
	SesameBLETransport(const SesameBLETransport&) = delete;
	SesameBLETransport& operator=(const SesameBLETransport&) = delete;
	bool send_data(const std::byte* pkt, size_t pkt_size, bool is_crypted);
	bool send_notify(Sesame::op_code_t op_code,
	                 Sesame::item_code_t item_code,
	                 const std::byte* data,
	                 size_t data_size,
	                 bool is_crypted,
	                 CryptHandler& crypt);
	decode_result_t decode(const std::byte* data, size_t size, CryptHandler& crypt);
	void disconnect();
	void reset();
	const std::byte* data() { return buffer.recv_buffer.data(); }
	size_t data_size() { return buffer.recv_size; }

 private:
	SesameBLEBackend& backend;
	SesameBLEBuffer buffer;
};

}  // namespace libsesame3bt::core
