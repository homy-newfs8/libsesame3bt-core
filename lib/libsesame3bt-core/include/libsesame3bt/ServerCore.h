#pragma once
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include "BLEBackend.h"
#include "Sesame.h"

namespace libsesame3bt::core {

class SesameServerCoreImpl;
using registration_callback_t = std::function<void(uint16_t session_id, const std::array<std::byte, Sesame::SECRET_SIZE>& secret)>;
using command_callback_t =
    std::function<Sesame::result_code_t(uint16_t session_id, Sesame::item_code_t cmd, const std::string& tag)>;

class SesameServerCore {
 public:
	SesameServerCore(ServerBLEBackend& backend, int max_sessions);
	SesameServerCore(const SesameServerCore&) = delete;
	SesameServerCore& operator=(const SesameServerCore&) = delete;
	virtual ~SesameServerCore();

	bool begin(libsesame3bt::Sesame::model_t model, const uint8_t (&uuid)[16]);
	void update();

	bool set_registered(const std::array<std::byte, Sesame::SECRET_SIZE>& secret);
	bool on_subscribed(uint16_t session_id);
	bool on_received(uint16_t session_id, const std::byte*, size_t);
	void on_disconnected(uint16_t session_id);
	bool is_registered() const;
	bool has_session(uint16_t session_id) const;
	size_t get_session_count() const;
	bool send_notify(std::optional<uint16_t> session_id,
	                 Sesame::op_code_t op_code,
	                 Sesame::item_code_t item_code,
	                 const std::byte* data,
	                 size_t size);

	void set_on_registration_callback(registration_callback_t callback);
	void set_on_command_callback(command_callback_t callback);

	std::tuple<std::string, std::string> create_advertisement_data_os3() const;

 private:
	std::unique_ptr<SesameServerCoreImpl> impl;
};

}  // namespace libsesame3bt::core
