#pragma once
#if defined(ESP32) || defined(ESP_PLATFORM)
#include <esp_timer.h>
#endif

namespace libsesame3bt {

uint32_t
millis() {
#if defined(ESP32) || defined(ESP_PLATFORM)
	return static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
#else
#error "millis not defined on this environment."
#endif
}

}  // namespace libsesame3bt
