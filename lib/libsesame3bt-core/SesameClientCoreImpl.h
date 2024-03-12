#pragma once

#include <mbedtls/ccm.h>
#include <array>
#include <atomic>
#include <cstddef>
#include <ctime>
#include <utility>
#include "Sesame.h"
#include "api_wrapper.h"
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

	SesameClientCoreImpl(SesameClientBackend& backend, SesameClientCore& core);
	SesameClientCoreImpl(const SesameClientCoreImpl&) = delete;
	SesameClientCoreImpl& operator=(const SesameClientCoreImpl&) = delete;
	virtual ~SesameClientCoreImpl();
	bool begin(Sesame::model_t model);
	bool set_keys(const std::array<std::byte, Sesame::PK_SIZE>& public_key,
	              const std::array<std::byte, Sesame::SECRET_SIZE>& secret_key);
	bool set_keys(const char* pk_str, const char* secret_str);
	bool on_connected();
	void on_received(const std::byte*, size_t);
	void on_disconnected();
	bool unlock(const char* tag);
	bool lock(const char* tag);
	/**
	 * @brief Click operation (for Bot only)
	 *
	 * @param tag %History tag (But it seems not recorded in bot)
	 * @return True if the command sent successfully
	 */
	bool click(const char* tag);
	bool request_history();
	bool is_session_active() const { return state.load() == SesameClientCore::state_t::active; }
	void set_status_callback(SesameClientCore::status_callback_t callback) { lock_status_callback = callback; }
	void set_state_callback(SesameClientCore::state_callback_t callback) { state_callback = callback; }
	void set_history_callback(SesameClientCore::history_callback_t callback) { history_callback = callback; }
	Sesame::model_t get_model() const { return model; }
	SesameClientCore::state_t get_state() const { return state.load(); }
	const std::variant<LockSetting, BotSetting>& get_setting() const { return setting; }
	void disconnect();

 private:
	friend class OS2Handler;
	friend class OS3Handler;
	static constexpr size_t MAX_RECV = 128;

	enum packet_kind_t { not_finished = 0, plain = 1, encrypted = 2 };  // do not use enum class to avoid warning in structure below.
	union __attribute__((packed)) packet_header_t {
		struct __attribute__((packed)) {
			bool is_start : 1;
			packet_kind_t kind : 2;
			std::byte unused : 5;
		};
		std::byte value;
	};
	static constexpr std::array<std::byte, 1> auth_add_data{};

	// session data
	api_wrapper<mbedtls_ccm_context> ccm_ctx{mbedtls_ccm_init, mbedtls_ccm_free};
	std::array<std::byte, 13> enc_iv;
	std::array<std::byte, 13> dec_iv;
	std::array<std::byte, MAX_RECV> recv_buffer;
	std::atomic<SesameClientCore::state_t> state{SesameClientCore::state_t::idle};
	size_t recv_size = 0;
	bool skipping = false;
	std::variant<LockSetting, BotSetting> setting;
	Status sesame_status;
	SesameClientCore::status_callback_t lock_status_callback{};
	SesameClientCore::state_callback_t state_callback{};
	SesameClientCore::history_callback_t history_callback{};
	Sesame::model_t model;
	std::optional<Handler> handler;

	bool is_key_set = false;
	bool is_key_shared = false;

	SesameClientBackend& backend;
	SesameClientCore& core;

	void reset_session();
	bool send_data(std::byte* pkt, size_t pkt_size, bool is_crypted);
	bool decrypt(const std::byte* in, size_t in_size, std::byte* out, size_t out_size);
	bool encrypt(const std::byte* in, size_t in_size, std::byte* out, size_t out_size);
	void handle_publish_initial();
	void handle_publish_mecha_setting();
	void handle_publish_mecha_status();
	void handle_response_login();
	void fire_status_callback();
	void update_state(SesameClientCore::state_t new_state);
	void fire_history_callback(const History& history);
	bool send_cmd_with_tag(Sesame::item_code_t code, const char* tag);

	// NimBLEClientCallbacks
	// virtual void onDisconnect(NimBLEClient* pClient) override;
};

}  // namespace libsesame3bt::core
