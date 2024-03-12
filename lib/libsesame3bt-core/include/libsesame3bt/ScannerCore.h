#pragma once
#include <string_view>
#include <tuple>
#include "Sesame.h"

namespace libsesame3bt::core {

std::tuple<Sesame::model_t, std::byte, bool> parse_advertisement(std::string_view manufactureData,
                                                                 std::string_view name,
                                                                 uint8_t (&uuid)[16]);

}  // namespace libsesame3bt::core
