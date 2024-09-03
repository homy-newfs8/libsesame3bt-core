#include <Arduino.h>
#include <Sesame.h>
#include <libsesame3bt/BLEBackend.h>
#include <libsesame3bt/ClientCore.h>
#include <libsesame3bt/ScannerCore.h>
#include <libsesame3bt/util.h>
#include "crypt.h"
#include "os3_iv.h"
#include "transport.h"

using libsesame3bt::core::CmacAes128;
using libsesame3bt::core::CryptHandler;
using libsesame3bt::core::OS3IVHandler;
using libsesame3bt::core::SesameBLEBackend;
using libsesame3bt::core::SesameBLETransport;
using decode_result_t = SesameBLETransport::decode_result_t;
namespace util = libsesame3bt::core::util;

class StubBackend : public SesameBLEBackend {
 public:
	virtual bool write_to_tx(const uint8_t* data, size_t size) { return false; }
	virtual void disconnect() {}
};

StubBackend backend;
SesameBLETransport transport{backend};
CryptHandler cr{std::in_place_type<OS3IVHandler>};

std::string
read_line() {
	String str;
	for (str = Serial.readString(); str.length() == 0; str = Serial.readString()) {
	}
	str.trim();
	return std::string(str.c_str());
}

bool as_peripheral;

/*
 * コンパイルの確認 および SESAME OS3 用メッセージ複合ツール
 *
 * libsesame3bt-coreの通常の使用方法は https://github.com/homy-newfs8/libsesame3bt を参照願います
 */
void
setup() {
	delay(5000);
	Serial.begin(115200);
	Serial.setTimeout(1000);

	Serial.println("Started");
	std::string line;
	Serial.println("input secret:");
	std::array<std::byte, 16> secret;
	while (true) {
		line = read_line();
		Serial.print("secret ");
		Serial.println(line.c_str());
		if (util::hex2bin(line, secret)) {
			break;
		}
		Serial.println("failed");
	}
	Serial.println("input nonce:");
	std::byte nonce[4]{};
	while (true) {
		line = read_line();
		Serial.print("nonce ");
		Serial.println(line.c_str());
		if (util::hex2bin(line, nonce)) {
			break;
		}
		Serial.println("failed");
	}
	CmacAes128 cmac;
	std::array<std::byte, 16> session_key;
	if (!cmac.set_key(secret) || !cmac.update(nonce) || !cmac.finish(session_key)) {
		Serial.println("Failed to create session key");
		return;
	}
	if (!cr.set_session_key(session_key.data(), session_key.size())) {
		Serial.println("Failed to set session key");
		return;
	}
	Serial.printf("session key=");
	Serial.println(util::bin2hex(session_key.data(), session_key.size()).c_str());
	cr.init_endec_iv(std::array<std::byte, 4>{}, nonce);
	std::array<std::byte, 128> buffer;
	bool prompt = true;
	while (true) {
		if (prompt) {
			Serial.println("input data or role switch C)entral or P)eripheral:");
			Serial.print(as_peripheral ? "P)" : "C)");
		}
		line = read_line();
		if (line == "C" || line == "c") {
			Serial.println("AS central");
			as_peripheral = false;
			continue;
		} else if (line == "P" || line == "p") {
			Serial.println("AS peripheral");
			as_peripheral = true;
			continue;
		}
		Serial.print("data ");
		Serial.println(line.c_str());
		size_t len;
		if (util::hex2bin(line, buffer, len)) {
			Serial.printf("decoding %u bytes\n", len);
			auto rc = transport.decode(buffer.data(), len, cr, as_peripheral);
			if (rc == decode_result_t::received) {
				Serial.printf("decoded(%u) ", transport.data_size());
				Serial.println(util::bin2hex(transport.data(), transport.data_size()).c_str());
			} else if (rc == decode_result_t::require_more) {
				Serial.print(">>");
				prompt = false;
				continue;
			} else {
				Serial.println("decode failed");
			}
		} else {
			Serial.println("invalid input");
		}
		prompt = true;
	}
}

void
loop() {
	delay(1000);
}
