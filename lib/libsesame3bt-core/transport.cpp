#include "transport.h"
#include <array>
#include "crypt.h"
#include "debug.h"
#include "libsesame3bt/util.h"

namespace libsesame3bt::core {

using util::to_byte;
using util::to_cptr;

namespace {

constexpr size_t FRAGMENT_SIZE = 19;

}

bool
SesameBLETransport::send_data(const std::byte* pkt, size_t pkt_size, bool is_crypted) {
	std::array<std::byte, 1 + FRAGMENT_SIZE> fragment;  // 1 for header
	int pos = 0;
	for (size_t remain = pkt_size; remain > 0;) {
		fragment[0] = packet_header_t{pos == 0,
		                              remain > FRAGMENT_SIZE ? packet_kind_t::not_finished
		                              : is_crypted           ? packet_kind_t::encrypted
		                                                     : packet_kind_t::plain,
		                              std::byte{0}}
		                  .value;
		size_t ssz = std::min(remain, FRAGMENT_SIZE);
		std::copy(pkt + pos, pkt + pos + ssz, &fragment[1]);
		if (!backend.write_to_tx(to_cptr(fragment), ssz + 1)) {
			DEBUG_PRINTLN("Failed to send data to the device");
			return false;
		}
		pos += ssz;
		remain -= ssz;
	}
	return true;
}

std::optional<result_t>
SesameBLETransport::decode(const std::byte* p, size_t len, CryptHandler& crypt) {
	if (len <= 1) {
		return result_t::invalid_packet;
	}
	packet_header_t h;
	h.value = p[0];
	if (h.is_start) {
		buffer.reset();
	}
	if (buffer.prev_result.has_value() && buffer.prev_result != result_t::success) {
		if (h.kind == packet_kind_t::encrypted) {
			crypt.update_dec_iv();
		}
		return buffer.prev_result;
	}
	if (buffer.recv_size + len - 1 > SesameBLEBuffer::MAX_RECV) {
		DEBUG_PRINTLN("Received data too long, skipping");
		if (h.kind == packet_kind_t::encrypted) {
			crypt.update_dec_iv();
		}
		buffer.prev_result = result_t::invalid_packet;
		return buffer.prev_result;
	}
	std::copy(p + 1, p + len, &buffer.recv_buffer[buffer.recv_size]);
	buffer.recv_size += len - 1;
	if (h.kind == packet_kind_t::not_finished) {
		// wait next packet
		return {};
	}
	if (h.kind == packet_kind_t::encrypted) {
		if (!crypt.is_key_shared()) {
			DEBUG_PRINTLN("Encrypted message received before key sharing");
			buffer.prev_result = result_t::invalid_state;
		} else if (buffer.recv_size < CryptHandler::CMAC_TAG_SIZE) {
			DEBUG_PRINTLN("Encrypted message too short");
			buffer.prev_result = result_t::invalid_packet;
		} else {
			std::array<std::byte, SesameBLEBuffer::MAX_RECV - CryptHandler::CMAC_TAG_SIZE> decrypted{};
			if (auto rc = crypt.decrypt(buffer.recv_buffer.data(), buffer.recv_size, &decrypted[0],
			                            buffer.recv_size - CryptHandler::CMAC_TAG_SIZE);
			    rc != result_t::success) {
				buffer.prev_result = rc;
			} else {
				std::copy(decrypted.cbegin(), decrypted.cbegin() + buffer.recv_size - CryptHandler::CMAC_TAG_SIZE, &buffer.recv_buffer[0]);
				buffer.recv_size -= CryptHandler::CMAC_TAG_SIZE;
				buffer.prev_result = result_t::success;
			}
		}
	} else if (h.kind == packet_kind_t::plain) {
		buffer.prev_result = result_t::success;
	} else {
		DEBUG_PRINTF("%u: Unexpected packet kind\n", static_cast<uint8_t>(h.kind));
		buffer.prev_result = result_t::invalid_packet;
	}
	return buffer.prev_result;
}

void
SesameBLETransport::reset() {
	buffer.reset();
}

// void
// SesameBLETransport::disconnect() {
// 	backend.disconnect();
// 	reset();
// }

result_t
SesameBLETransport::send_notify(Sesame::op_code_t op_code,
                                Sesame::item_code_t item_code,
                                const std::byte* data,
                                size_t data_size,
                                bool is_crypted,
                                CryptHandler& crypt) {
	const size_t pkt_size = 2 + data_size + (is_crypted ? Sesame::CMAC_TAG_SIZE : 0);  // 2 for op/item, 4 for encrypted tag
	std::byte pkt[pkt_size];
	if (is_crypted) {
		std::byte plain[2 + data_size];
		plain[0] = to_byte(op_code);
		plain[1] = to_byte(item_code);
		std::copy(data, data + data_size, &plain[2]);
		if (auto rc = crypt.encrypt(plain, sizeof(plain), pkt, sizeof(pkt)); rc != result_t::success) {
			return rc;
		}
	} else {
		pkt[0] = to_byte(op_code);
		pkt[1] = to_byte(item_code);
		std::copy(data, data + data_size, &pkt[2]);
	}
	return send_data(pkt, pkt_size, is_crypted) ? result_t::success : result_t::transport_failure;
}

}  // namespace libsesame3bt::core
