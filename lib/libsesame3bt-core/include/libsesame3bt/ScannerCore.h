#pragma once
#include <string_view>
#include <tuple>
#include "Sesame.h"

namespace libsesame3bt::core {

std::tuple<Sesame::model_t, std::byte, bool> parse_advertisement(std::string_view manufacture_data,
                                                                 std::string_view name,
                                                                 uint8_t (&uuid)[16]);
std::tuple<std::string, std::string> create_advertisement_data_os3(Sesame::model_t model,
                                                                   std::byte flag,
                                                                   const uint8_t (&uuid)[16]);

}  // namespace libsesame3bt::core
