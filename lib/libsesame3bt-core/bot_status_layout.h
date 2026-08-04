#pragma once

#include <cstddef>
#include "Sesame.h"

namespace libsesame3bt::core {

constexpr bool
uses_compact_bot_status_layout(Sesame::model_t model, std::size_t payload_size) {
	const auto compact_size = sizeof(Sesame::mecha_bot_2_status_t);
	// Longer Bot 2 payloads use the generic mecha_status_5_t layout. Bot 3
	// extends the compact Bot 2 layout, so trailing fields are allowed there.
	return (model == Sesame::model_t::sesame_bot_2 && payload_size == compact_size) ||
	       (model == Sesame::model_t::sesame_bot_3 && payload_size >= compact_size);
}

}  // namespace libsesame3bt::core
