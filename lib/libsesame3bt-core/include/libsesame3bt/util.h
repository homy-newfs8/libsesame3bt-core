#pragma once
#include <array>
#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>

namespace libsesame3bt::core {
namespace util {

std::string_view truncate_utf8(std::string_view str, size_t limit);
std::string_view cleanup_tail_utf8(std::string_view str);

int8_t nibble(char c);
char hexchar(int b, bool upper = false);

template <size_t N>
bool
hex2bin(std::string_view str, std::array<std::byte, N>& out) {
	if (str.length() != N * 2) {
		return false;
	}
	for (int i = 0; i < N; i++) {
		int8_t n1 = nibble(str[i * 2]);
		int8_t n2 = nibble(str[i * 2 + 1]);
		if (n1 < 0 || n2 < 0) {
			return false;
		}
		out[i] = std::byte{static_cast<uint8_t>((n1 << 4) + n2)};
	}
	return true;
}

std::string bin2hex(const std::byte* data, size_t data_size, bool upper = false);

template <size_t N>
static inline uint8_t*
to_ptr(std::array<std::byte, N>& array) {
	return reinterpret_cast<uint8_t*>(array.data());
}

template <size_t N>
static inline const uint8_t*
to_cptr(const std::array<std::byte, N>& array) {
	return reinterpret_cast<const uint8_t*>(array.data());
}

static inline uint8_t*
to_ptr(std::byte* p) {
	return reinterpret_cast<uint8_t*>(p);
}

static inline const uint8_t*
to_cptr(const std::byte* p) {
	return reinterpret_cast<const uint8_t*>(p);
}

template <typename T>
static inline constexpr std::byte
to_byte(T v) {
	return std::byte{static_cast<uint8_t>(v)};
}

}  // namespace util
}  // namespace libsesame3bt::core
