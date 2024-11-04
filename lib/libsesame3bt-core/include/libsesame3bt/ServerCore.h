#pragma once
#include <functional>
#include <memory>
#include <string>
#include "BLEBackend.h"
#include "Sesame.h"

namespace libsesame3bt::core {

class SesameServerCoreImpl;
using registration_callback_t = std::function<void(const std::array<std::byte, Sesame::SECRET_SIZE>& secret)>;

using command_callback_t = std::function<Sesame::result_code_t(Sesame::item_code_t cmd, const std::string& tag)>;

class SesameServerCore {
 public:
	SesameServerCore(ServerBLEBackend& backend);
	SesameServerCore(const SesameServerCore&) = delete;
	SesameServerCore& operator=(const SesameServerCore&) = delete;
	virtual ~SesameServerCore();

	bool begin(libsesame3bt::Sesame::model_t model, const uint8_t (&uuid)[16]);
	void update();

	bool generate_keypair();
	bool load_key(const std::array<std::byte, Sesame::SK_SIZE>& privkey);
	bool export_keypair(std::array<std::byte, Sesame::PK_SIZE>& pubkey, std::array<std::byte, Sesame::SK_SIZE>& privkey);
	bool set_registered(const std::array<std::byte, Sesame::SECRET_SIZE>& secret);
	void on_subscribed(uint16_t session_id);
	void on_received(uint16_t session_id, const std::byte*, size_t);
	void on_disconnected(uint16_t session_id);
	bool is_registered();
	size_t get_session_count() const;

	void set_on_registration_callback(registration_callback_t callback);
	void set_on_command_callback(command_callback_t callback);

	std::tuple<std::string, std::string> create_advertisement_data_os3();

 private:
	std::unique_ptr<SesameServerCoreImpl> impl;
};

}  // namespace libsesame3bt::core
