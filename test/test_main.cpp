#include <Arduino.h>
#include <libsesame3bt/BLEBackend.h>
#include <libsesame3bt/util.h>
#include <unity.h>
#include <string>
#include "crypt.h"
#include "os3_iv.h"
#include "transport.h"
#if __has_include("mysesame-config.h")
#include "mysesame-config.h"
#endif

#if !defined(SESAME_SECRET)
#define SESAME_SECRET "**REPLACE**"
#endif
#if !defined(SESAME_PK)
#define SESAME_PK "**REPLACE**"
#endif
#if !defined(SESAME_ADDRESS)
#define SESAME_ADDRESS "**REPLACE**"
#endif
#if !defined(SESAME_MODEL)
#define SESAME_MODEL Sesame::model_t::sesame_3
#endif

#define TEST_UTILITY 1
#define TEST_BLE 0

namespace util = libsesame3bt::core::util;
using namespace libsesame3bt::core;

class TestBackend : public SesameBLEBackend {
 public:
	std::vector<std::vector<std::byte>> buffer;
	virtual bool write_to_tx(const uint8_t* data, size_t size) override {
		const auto* p = reinterpret_cast<const std::byte*>(data);
		buffer.push_back({p, p + size});
		return true;
	}
};

CryptHandler periph_crypt{std::in_place_type<OS3IVHandler>, true};
CryptHandler central_crypt{std::in_place_type<OS3IVHandler>, false};
TestBackend backend;
SesameBLETransport transport{backend};

std::byte key[16];
std::byte nonce[4];

std::byte data[100];
std::byte buffer[std::size(data) + CryptHandler::CMAC_TAG_SIZE];

std::byte large_data[SesameBLEBuffer::MAX_RECV + 1];
std::byte large_buffer[std::size(large_data) + CryptHandler::CMAC_TAG_SIZE];

extern "C" void
setUp() {
	for (uint8_t i = 0; auto& p : key) {
		p = std::byte{i++};
	}
	for (uint8_t i = 0; auto& p : nonce) {
		p = std::byte{i++};
	}
	for (uint8_t i = 0; auto& p : data) {
		p = std::byte{i++};
	}
	for (uint8_t i = 0; auto& p : large_data) {
		p = std::byte{i++};
	}
	backend.buffer.clear();
	periph_crypt.reset_session_key();
	central_crypt.reset_session_key();
}
extern "C" void
tearDown() {}

void
test_transport_normal() {
	TEST_ASSERT_TRUE(periph_crypt.set_session_key(key, std::size(key), {}, nonce));
	TEST_ASSERT_TRUE(central_crypt.set_session_key(key, std::size(key), {}, nonce));

	// plain
	TEST_ASSERT_TRUE(transport.send_data(data, std::size(data), false));
	for (auto& packet : backend.buffer) {
		auto result = transport.decode(packet.data(), packet.size(), periph_crypt);
		if (result == result_t::success) {
			break;
		}
		TEST_ASSERT_TRUE_MESSAGE(!result.has_value(), ("result = " + std::to_string(static_cast<uint8_t>(*result))).c_str());
	}
	TEST_ASSERT_EQUAL(std::size(data), transport.data_size());
	TEST_ASSERT_TRUE(std::equal(transport.data(), transport.data() + transport.data_size(), data, data + std::size(data)));

	// crypted
	TEST_ASSERT_EQUAL(result_t::success, central_crypt.encrypt(data, std::size(data), buffer, std::size(buffer)));
	backend.buffer.clear();
	TEST_ASSERT_TRUE(transport.send_data(buffer, std::size(buffer), true));
	for (auto& packet : backend.buffer) {
		auto result = transport.decode(packet.data(), packet.size(), periph_crypt);
		if (result == result_t::success) {
			break;
		}
		TEST_ASSERT_TRUE_MESSAGE(!result.has_value(), ("result = " + std::to_string(static_cast<uint8_t>(*result))).c_str());
	}
	TEST_ASSERT_EQUAL(std::size(data), transport.data_size());
	TEST_ASSERT_TRUE(std::equal(transport.data(), transport.data() + transport.data_size(), data, data + std::size(data)));

	for (size_t size = 0; size < std::size(data); size++) {
		TEST_MESSAGE(("test for " + std::to_string(size) + " bytes").c_str());

		TEST_ASSERT_EQUAL(result_t::success, central_crypt.encrypt(data, size, buffer, size + CryptHandler::CMAC_TAG_SIZE));
		backend.buffer.clear();
		TEST_ASSERT_TRUE(transport.send_data(buffer, size + CryptHandler::CMAC_TAG_SIZE, true));
		for (auto& packet : backend.buffer) {
			auto result = transport.decode(packet.data(), packet.size(), periph_crypt);
			if (result == result_t::success) {
				break;
			}
			TEST_ASSERT_TRUE_MESSAGE(!result.has_value(), ("result = " + std::to_string(static_cast<uint8_t>(*result))).c_str());
		}
		TEST_ASSERT_EQUAL(size, transport.data_size());
		TEST_ASSERT_TRUE(std::equal(transport.data(), transport.data() + size, data, data + size));
	}
}

void
test_invalid_state() {
	// both crypt handler not initialized

	TEST_ASSERT_EQUAL(result_t::invalid_state, central_crypt.encrypt(data, std::size(data), buffer, std::size(buffer)));

	// initialize central
	TEST_ASSERT_TRUE(central_crypt.set_session_key(key, std::size(key), {}, nonce));

	TEST_ASSERT_EQUAL(result_t::success, central_crypt.encrypt(data, std::size(data), buffer, std::size(buffer)));

	backend.buffer.clear();
	TEST_ASSERT_TRUE(transport.send_data(buffer, std::size(buffer), true));

	for (auto& packet : backend.buffer) {
		auto result = transport.decode(packet.data(), packet.size(), periph_crypt);
		TEST_ASSERT_FALSE(result == result_t::success);
		TEST_ASSERT_TRUE(!result.has_value() || result == result_t::invalid_state);
	}

	// initialize peripheral
	TEST_ASSERT_TRUE(periph_crypt.set_session_key(key, std::size(key), {}, nonce));
	for (auto& packet : backend.buffer) {
		auto result = transport.decode(packet.data(), packet.size(), periph_crypt);
		if (result == result_t::success) {
			break;
		}
		TEST_ASSERT_TRUE_MESSAGE(!result.has_value(), ("result = " + std::to_string(static_cast<uint8_t>(*result))).c_str());
	}
	TEST_ASSERT_EQUAL(std::size(data), transport.data_size());
	TEST_ASSERT_TRUE(std::equal(transport.data(), transport.data() + transport.data_size(), data, data + std::size(data)));
}

void
test_invalid_packet() {
	TEST_ASSERT_TRUE(periph_crypt.set_session_key(key, std::size(key), {}, nonce));
	TEST_ASSERT_TRUE(central_crypt.set_session_key(key, std::size(key), {}, nonce));

	// plain
	TEST_ASSERT_TRUE(transport.decode(data, 1, periph_crypt) == result_t::invalid_packet);

	TEST_ASSERT_TRUE(transport.send_data(large_data, std::size(large_data), false));  // currently not checked
	for (auto& packet : backend.buffer) {
		auto result = transport.decode(packet.data(), packet.size(), periph_crypt);
		TEST_ASSERT_TRUE_MESSAGE(
		    !result.has_value() || result == result_t::invalid_packet,
		    ("result=" + (result.has_value() ? std::to_string(static_cast<uint8_t>(*result)) : "(empty)")).c_str());
	}

	// crypted
	TEST_ASSERT_EQUAL(result_t::success,
	                  central_crypt.encrypt(large_data, std::size(large_data), large_buffer, std::size(large_buffer)));
	backend.buffer.clear();
	TEST_ASSERT_TRUE(transport.send_data(large_buffer, std::size(large_buffer), true));
	for (auto& packet : backend.buffer) {
		auto result = transport.decode(packet.data(), packet.size(), periph_crypt);
		TEST_ASSERT_FALSE(result == result_t::success);
		TEST_ASSERT_TRUE(!result.has_value() || result == result_t::invalid_packet);
	}
}

void
setup() {
	Serial.begin(115200);
	delay(3000);
	UNITY_BEGIN();
	RUN_TEST(test_transport_normal);
	RUN_TEST(test_invalid_state);
	RUN_TEST(test_invalid_packet);
	UNITY_END();
}

void
loop() {
	delay(100);
}
