#pragma once
#ifdef ESP32
#include <esp_timer.h>
#endif

namespace libsesame3bt {

uint32_t
millis() {
#ifdef ESP32
	return static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
#else
#error "millis not defined on this environment."
#endif
}

}  // namespace libsesame3bt
