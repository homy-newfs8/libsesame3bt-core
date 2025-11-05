# libsesame3bt-core
Bluetooth LE access library for CANDY HOUSE SESAME 5 / SESAME 5 PRO / SESAME Bot 2 / SESAME bike 2 / SESAME 4 / SESAME 3 / SESAME bot / SESAME 3 bike (SESAME Cycle)

# Usage
This library contains the message processing part. BLE connections must be handled outside of this library.

1. Prepare a callback object inherited from `SesameClientBackend`
1. Create `SesameClientCore` instance.
1. Initialize with `SesameClientCore::begin()` and `SesameClientCore::set_key()`.
1. Connect to SESAME by any BLE API (use BLE MAC Address of SESAME).
1. Prepare to access service (UUID=`Sesame::SESAME3_SRV_UUID`).
1. Prepare to send data to Tx characteristic in above service (UUID=`Sesame::TxUUID`).
1. Prepare to receive notification from Rx characteristic (UUID=`Sesame::RxUUID`).
1. When notification received from above Rx characteristic, call `SesameClientCore::on_received()` with the notification data.
1. When `SesameClientBackend::write_to_tx()` is called, send the data to above Tx characteristic(w/o request response).
1. When `SesameClientBackend::disconnect()` is called, disconnect from SESAME.
1. When disconnected from SESAME, call `SesameClientCore::on_disconnected()`.

# Dependency
- [Mbed TLS](https://github.com/Mbed-TLS/mbedtls).

If your execution environment includes Mbed TLS's CMAC functions, define USE_FRAMEWORK_MBEDTLS_CMAC at compile time.

# Integrated library example
[libsesame3bt](https://github.com/homy-newfs8/libsesame3bt) is a library that integrates this library with the ESP32 / Android / NimBLE libraries.

With [libsesame3bt](https://github.com/homy-newfs8/libsesame3bt), you can control SESAME as follows.

platformmio.ini
```ini
[env]
platform = https://github.com/pioarduino/platform-espressif32/releases/download/stable/platform-espressif32.zip
framework = arduino
lib_deps = https://github.com/homy-newfs8/libsesame3bt#0.30.0
build_flags = -DCONFIG_MBEDTLS_CMAC_C -DUSE_FRAMEWORK_MBEDTLS_CMAC
````

# Example
## Scan
```C++
using libsesame3bt::SesameInfo;
using libsesame3bt::SesameScanner;

void do_scan() {
	SesameScanner& scanner = SeameScanner::get();
	std::vector<SesameInfo> results;

	scanner.scan(10, [&results](SesameScanner& _scanner, const SesameInfo* _info)) {
		results.push_back(*_info);
	}
	Serial.printf("%u devices found\n", results.size());
	for (const auto& it : results) {
		Serial.printf("%s: %s: model=%u, registered=%u\n", it.uuid.toString().c_str(), it.address.toString().c_str(),
		                (unsigned int)it.model, it.flags.registered);
	}
}

```

## Control
```C++
using libsesame3bt::Sesame;
using libsesame3bt::SesameClient;
using libsesame3bt::SesameInfo;

void do_unlock_lock() {
	SesameClient client{};
	// Use SesameInfo to initialize
	client.begin(sesameInfo.addr, sesameInfo.model);
	// or specify bluetooth address and model type directory
	client.begin(BLEAddress{"***your device address***", BLE_ADDR_RANDOM}, Sesame::model_t::sesame_5);

	client.set_keys("", SESAME_SECRET);
	client.connect();
	// Wait for connection and authentication done
	// See example/by_scan/by_scan.cpp for details
	client.unlock("**TAG**");
	delay(3000);
	client.lock("***TAG***");
}
```
# Sample App
* [ESP32Sesame3App](http://github.com/homy-newfs8/ESP32Sesame3App)

# Integrate to your Home Automation system without code
* ESPHome External Component [esphome-sesame3](https://github.com/homy-newfs8/esphome-sesame3)

# Server feature
Starting with version 0.8.0, the Sesame Server feature has been added, allowing the device to pretend to be a SESAME 5 device and listen for and handle push button events from CANDY HOUSE Remote/nano and open/close events from the Open Sensor.

See [libsesame3bt-server](https://github.com/homy-newfs8/libsesame3bt-server) library for usage.

# License
MIT AND Apache-2.0

Almost all code is licensed under MIT-style license. Files under [src/mbedtls-extra](src/mbedtls-extra) are licensed under Apache-2.0.

# See Also
[README.ja.md](README.ja.md)
