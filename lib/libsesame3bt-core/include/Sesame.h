#pragma once
#include <algorithm>
#include <array>
#include <cstddef>

namespace libsesame3bt {

/// @warning Not well defined values, may be changed in future
enum class trigger_type_t : uint8_t {
	ic_card = 0,        // touch, face
	face_finger = 1,    // face
	face = 3,           // face
	face_vein = 4,      // face
	touch_finger = 6,   // touch success, unknown fingerprint
	open_sensor = 7,    // open sensor
	face_close = 9,     // face close switch, unknown fingerprint
	remote = 10,        // remote
	remote_nano = 11,   // remote nano
	android_ble = 14,   // android app (from Android SDK)
	android_wifi = 16,  // from Android SDK
};

class Sesame {
 public:
	static constexpr size_t TOKEN_SIZE = 4;
	static constexpr uint16_t COMPANY_ID = 0x055a;
	static inline const char* SESAME3_SRV_UUID{"fd81"};
	static inline const char* TxUUID{"16860002-a5ae-9856-b6d3-dbb4c676993e"};
	static inline const char* RxUUID{"16860003-a5ae-9856-b6d3-dbb4c676993e"};
	static constexpr size_t PK_SIZE = 64;
	static constexpr size_t SK_SIZE = 32;
	static constexpr size_t SECRET_SIZE = 16;
	static constexpr size_t CMAC_TAG_SIZE = 4;

	static constexpr size_t MAX_CMD_TAG_SIZE_OS2 = 21;
	static constexpr size_t MAX_CMD_TAG_SIZE_OS3 = 29;
	static constexpr size_t MAX_CMD_TAG_SIZE_OS3_V2 = 32;  // Hex-encoded UUID
	static constexpr size_t MAX_HISTORY_TAG_SIZE =
	    std::max(std::max(MAX_CMD_TAG_SIZE_OS2, MAX_CMD_TAG_SIZE_OS3), MAX_CMD_TAG_SIZE_OS3_V2);

	enum class model_t : int8_t {
		unknown = -1,
		sesame_3 = 0,
		wifi_2 = 1,
		sesame_bot = 2,
		sesame_bike = 3,
		sesame_cycle = 3,
		sesame_4 = 4,
		sesame_5 = 5,
		sesame_bike_2 = 6,
		sesame_5_pro = 7,
		open_sensor_1 = 8,
		sesame_touch_pro = 9,
		sesame_touch = 10,
		ble_connector = 11,
		hub3 = 13,
		remote = 14,
		remote_nano = 15,
		sesame_5_us = 16,
		sesame_bot_2 = 17,
		sesame_face_pro = 18,
		sesame_face = 19,
		sesame_6 = 20,
		sesame_6_pro = 21,
	};
	enum class motor_status_t : uint8_t { idle = 0, locking, holding, unlocking };
	enum class op_code_t : uint8_t {
		create = 1,
		read = 2,
		update = 3,
		delete_ = 4,
		sync = 5,
		async = 6,
		response = 7,
		publish = 8,
		undefine = 16
	};
	enum class item_code_t : uint8_t {
		none = 0,
		registration = 1,
		login = 2,
		user = 3,
		history = 4,
		version_tag = 5,
		disconnect_reboot_now = 6,
		enable_dfu = 7,
		time = 8,
		ble_connection_param = 9,
		ble_adv_param = 10,
		autolock = 11,
		server_adv_kick = 12,
		ssmtoken = 13,
		initial = 14,
		irer = 15,
		time_phone = 16,
		mech_setting = 80,
		mech_status = 81,
		lock = 82,
		unlock = 83,
		move_to = 84,
		drive_direction = 85,
		stop = 86,
		detect_dir = 87,
		toggle = 88,
		click = 89,
		door_open = 90,    // open sensor
		door_closed = 91,  // open sensor
		add_sesame = 101,
		pub_ssm_key = 102,
		remove_sesame = 103,
	};
	enum class result_code_t : uint8_t {
		success = 0,
		invalid_format = 1,
		not_supported = 2,
		storage_fail = 3,
		invalid_sig = 4,
		not_found = 5,
		unknown = 6,
		busy = 7,
		invalid_param = 8
	};
	enum class history_type_t : uint8_t {
		none = 0,
		ble_lock = 1,  ///< SESAMEへBT APIで
		ble_unlock,
		time_changed,
		autolock_updated,
		mech_setting_updated,
		autolock,
		manual_locked,
		manual_unlocked,
		manual_else,
		drive_locked,
		drive_unlocked,
		drive_failed,
		ble_adv_param_updated,
		wm2_lock,  ///< セサミアプリからBT→WM2⇒SESAME、セサミアプリから WiFi→(Web)→WM2⇒SESAME
		wm2_unlock,
		web_lock,
		web_unlock,
		ble_click,           // BT API→Bot, セサミアプリ WiFi→(Web)→WM2=>Botの両方
		drive_clicked = 21,  // observed value
	};

	enum class os_ver_t : uint8_t { unknown = 0, os2 = 2, os3 = 3 };

	static os_ver_t get_os_ver(model_t model) {
		int8_t v = static_cast<int8_t>(model);
		if (v < 0 || v > static_cast<int8_t>(model_t::sesame_face)) {
			return os_ver_t::unknown;
		} else if (v >= static_cast<int8_t>(model_t::sesame_3) && v <= static_cast<int8_t>(model_t::sesame_4)) {
			return os_ver_t::os2;
		} else {
			return os_ver_t::os3;
		}
	}

	union __attribute__((packed)) mecha_setting_t {
		struct __attribute((packed)) {
			int16_t lock_position;
			int16_t unlock_position;
		} lock;
		struct __attribute__((packed)) {
			uint8_t user_pref_dir;
			uint8_t lock_sec;
			uint8_t unlock_sec;
			uint8_t click_lock_sec;
			uint8_t click_hold_sec;
			uint8_t click_unlock_sec;
			uint8_t button_mode;
		} bot;
		std::byte data[12]{};
	};
	struct __attribute__((packed)) mecha_setting_5_t {
		int16_t lock_position;
		int16_t unlock_position;
		int16_t auto_lock_sec;
	};

	union __attribute__((packed)) mecha_status_t {
		struct __attribute__((packed)) mecha_lock_status_t {
			uint16_t battery;
			int16_t target;
			int16_t position;
			uint8_t retcode;
			uint8_t unknown1 : 1;
			bool in_lock : 1;
			bool in_unlock : 1;
			uint8_t unknown2 : 2;
			bool is_battery_critical : 1;
		} lock;
		struct __attribute__((packed)) mecha_bot_status_t {
			uint16_t battery;
			uint16_t unknown1;
			motor_status_t motor_status;
			uint8_t unknown2[2];
			bool not_stop : 1;
			bool in_lock : 1;
			bool in_unlock : 1;
			bool unknown3 : 2;
			bool is_battery_critical : 1;
		} bot;
		std::byte data[8]{};
	};
	struct __attribute__((packed)) mecha_bot_2_status_t {
		uint16_t battery;
		bool unknown1 : 1;
		bool unknown2 : 1;
		bool is_idle : 1;
	};
	struct __attribute__((packed)) mecha_status_5_t {
		int16_t battery;
		int16_t target;
		int16_t position;
		bool is_clutch_failed : 1;
		bool in_lock : 1;
		bool is_unlock_range : 1;
		bool is_critical : 1;
		bool is_stop : 1;
		bool is_battery_critical : 1;
		bool is_clockwise : 1;
	};
	struct __attribute__((packed)) publish_initial_t {
		std::byte token[TOKEN_SIZE];
	};
	struct __attribute__((packed)) message_header_t {
		op_code_t op_code;
		item_code_t item_code;
	};
	struct __attribute__((packed)) publish_mecha_status_t {
		mecha_status_t status;
	};
	struct __attribute__((packed)) publish_mecha_status_5_t {
		mecha_status_5_t status;
	};
	struct __attribute__((packed)) publish_mecha_setting_t {
		mecha_setting_t setting;
	};
	struct __attribute__((packed)) publish_mecha_setting_5_t {
		mecha_setting_5_t setting;
	};
	struct __attribute__((packed)) response_login_t {
		uint8_t op_code_2;
		result_code_t result;
		uint32_t timestamp;
		std::byte _unknown[4];
		mecha_setting_t mecha_setting;
		mecha_status_t mecha_status;
	};
	struct __attribute__((packed)) response_login_5_t {
		result_code_t result;
		uint32_t timestamp;
	};
	struct __attribute__((packed)) response_history_t {
		uint8_t op_code_2;
		result_code_t result;
		int32_t record_id;
		history_type_t type;
		long long timestamp;
	};
	struct __attribute__((packed)) response_history_5_t {
		result_code_t result;
		int32_t record_id;
		history_type_t type;
		uint32_t timestamp;
		mecha_status_5_t mecha_status;
	};
	struct __attribute__((packed)) os3_cmd_registration_t {
		std::array<std::byte, PK_SIZE> public_key;
		uint32_t timestamp;
	};
	struct __attribute__((packed)) os3_operation_tag_t {
		uint8_t len;
		char data[MAX_CMD_TAG_SIZE_OS3];
	};
	struct __attribute__((packed)) os3_cmd_login_t {
		std::array<std::byte, 4> auth_code;
	};
	struct __attribute__((packed)) response_registration_5_t {
		result_code_t result;
		mecha_status_5_t mecha_status;
		mecha_setting_5_t mecha_setting;
		std::array<std::byte, PK_SIZE> public_key;
	};
	struct __attribute__((packed)) response_os3_t {
		result_code_t result;
	};

 private:
	Sesame() = delete;
	~Sesame() = delete;
};

}  // namespace libsesame3bt
