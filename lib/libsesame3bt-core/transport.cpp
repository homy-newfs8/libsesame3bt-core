#include "transport.h"
#include <array>
#include "crypt.h"
#include "debug.h"
#include "libsesame3bt/util.h"

namespace libsesame3bt::core {

using util::to_cptr;

namespace {

constexpr size_t FRAGMENT_SIZE = 19;

}

bool
SesameBLETransport::send_data(const std::byte* pkt, size_t pkt_size, bool is_crypted) {
	std::array<std::byte, 1 + FRAGMENT_SIZE> fragment;  // 1 for header
	int pos = 0;
	for (size_t remain = pkt_size; remain > 0;) {
		fragment[0] = packet_header_t{
		    pos == 0,
		    remain > FRAGMENT_SIZE ? packet_kind_t::not_finished
		    : is_crypted           ? packet_kind_t::encrypted
		                           : packet_kind_t::plain,
		    std::byte{0}}.value;
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

using decode_result_t = SesameBLETransport::decode_result_t;

decode_result_t
SesameBLETransport::decode(const std::byte* p, size_t len, CryptHandler& crypt) {
	if (len <= 1) {
		return decode_result_t::dropped;
	}
	packet_header_t h;
	h.value = p[0];
	if (h.is_start) {
		buffer.skipping = false;
		buffer.recv_size = 0;
	}
	if (buffer.skipping) {
		if (h.kind == packet_kind_t::encrypted) {
			crypt.update_dec_iv();
		}
		return decode_result_t::skipping;
	}
	if (buffer.recv_size + len - 1 > SesameBLEBuffer::MAX_RECV) {
		DEBUG_PRINTLN("Received data too long, skipping");
		buffer.skipping = true;
		if (h.kind == packet_kind_t::encrypted) {
			crypt.update_dec_iv();
		}
		return decode_result_t::skipping;
	}
	std::copy(p + 1, p + len, &buffer.recv_buffer[buffer.recv_size]);
	buffer.recv_size += len - 1;
	if (h.kind == packet_kind_t::not_finished) {
		// wait next packet
		return decode_result_t::require_more;
	}
	buffer.skipping = true;
	if (h.kind == packet_kind_t::encrypted) {
		if (buffer.recv_size < CryptHandler::CMAC_TAG_SIZE) {
			DEBUG_PRINTLN("Encrypted message too short");
			return decode_result_t::skipping;
		}
		if (!crypt.is_key_shared()) {
			DEBUG_PRINTLN("Encrypted message received before key sharing");
			return decode_result_t::skipping;
		}
		std::array<std::byte, SesameBLEBuffer::MAX_RECV - CryptHandler::CMAC_TAG_SIZE> decrypted{};
		if (!crypt.decrypt(buffer.recv_buffer.data(), buffer.recv_size, &decrypted[0],
		                   buffer.recv_size - CryptHandler::CMAC_TAG_SIZE)) {
			return decode_result_t::skipping;
		}
		std::copy(decrypted.cbegin(), decrypted.cbegin() + buffer.recv_size - CryptHandler::CMAC_TAG_SIZE, &buffer.recv_buffer[0]);
		buffer.recv_size -= CryptHandler::CMAC_TAG_SIZE;
	} else if (h.kind != packet_kind_t::plain) {
		DEBUG_PRINTF("%u: Unexpected packet kind\n", static_cast<uint8_t>(h.kind));
		return decode_result_t::skipping;
	}
	if (buffer.recv_size < sizeof(Sesame::message_header_t)) {
		DEBUG_PRINTF("%u: Short notification, ignore\n", buffer.recv_size);
		return decode_result_t::skipping;
	}
	return decode_result_t::received;
}

void
SesameBLETransport::reset() {
	buffer.reset();
}

void
SesameBLETransport::disconnect() {
	backend.disconnect();
	reset();
}

}  // namespace libsesame3bt::core
