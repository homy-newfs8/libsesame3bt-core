#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <ctime>
#include <optional>
#include <string_view>
#include <utility>
#include "Sesame.h"
#include "api_wrapper.h"
#include "crypt.h"
#include "handler.h"
#include "libsesame3bt/ClientCore.h"

namespace libsesame3bt::core {

/**
 * @brief Sesame client
 *
 */
class SesameClientCoreImpl {
 public:
	static constexpr size_t MAX_CMD_TAG_SIZE_OS2 = 21;
	static constexpr size_t MAX_CMD_TAG_SIZE_OS3 = 29;
	static constexpr size_t MAX_HISTORY_TAG_SIZE = std::max(MAX_CMD_TAG_SIZE_OS2, MAX_CMD_TAG_SIZE_OS3);

	SesameClientCoreImpl(SesameBLEBackend& backend, SesameClientCore& core);
	SesameClientCoreImpl(const SesameClientCoreImpl&) = delete;
	SesameClientCoreImpl& operator=(const SesameClientCoreImpl&) = delete;
	virtual ~SesameClientCoreImpl();
	result_t begin(Sesame::model_t model);
	result_t set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
	                  const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key);
	result_t set_keys(std::string_view pk_str, std::string_view secret_str);
	result_t on_received(const std::byte*, size_t);
	void on_disconnected();
	result_t unlock(std::string_view tag);
	result_t unlock(history_tag_type_t type, const std::array<std::byte, HISTORY_TAG_UUID_SIZE>& uuid);
	result_t lock(std::string_view tag);
	result_t lock(history_tag_type_t type, const std::array<std::byte, HISTORY_TAG_UUID_SIZE>& uuid);
	result_t click(std::optional<uint8_t> script_no);
	result_t click(std::string_view tag);
	result_t request_history();
	bool is_session_active() const { return state.load() == state_t::active; }
	void set_status_callback(status_callback_t callback) { lock_status_callback = callback; }
	void set_state_callback(state_callback_t callback) { state_callback = callback; }
	void set_history_callback(history_callback_t callback) { history_callback = callback; }
	void set_registered_devices_callback(registered_devices_callback_t callback) { registered_devices_callback = callback; }
	void set_setting_callback(setting_callback_t callback) { setting_callback = callback; }
	Sesame::model_t get_model() const { return model; }
	state_t get_state() const { return state.load(); }
	bool has_setting() const;
	result_t request_status();
	bool is_key_set() const { return _is_key_set; }

 private:
	friend class OS2Handler;
	friend class OS3Handler;

	std::atomic<state_t> state{state_t::idle};
	Status sesame_status;
	status_callback_t lock_status_callback{};
	state_callback_t state_callback{};
	history_callback_t history_callback{};
	registered_devices_callback_t registered_devices_callback{};
	setting_callback_t setting_callback{};
	Sesame::model_t model;
	SesameBLETransport transport;
	std::optional<CryptHandler> crypt;
	std::optional<Handler> handler;

	bool _is_key_set = false;

	SesameClientCore& core;

	result_t handle_publish_initial();
	void fire_status_callback();
	void update_state(state_t new_state);
	void fire_history_callback(const History& history);
	result_t send_cmd_with_tag(Sesame::item_code_t code, std::string_view tag);
	result_t send_cmd_with_uuid_tag(Sesame::item_code_t code,
	                                history_tag_type_t type,
	                                const std::array<std::byte, HISTORY_TAG_UUID_SIZE>& uuid);
	result_t handle_publish_pub_key_sesame(const std::byte* in, size_t in_size);
	void setting_received(const std::variant<LockSetting, BotSetting>& setting);
};

}  // namespace libsesame3bt::core
