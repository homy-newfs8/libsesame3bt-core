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

bool hex2bin(std::string_view str, std::byte* out, size_t limit, size_t& out_len);

template <size_t N>
bool
hex2bin(std::string_view str, std::byte (&out)[N], size_t& out_len) {
	return hex2bin(str, out, N, out_len);
}

template <size_t N>
bool
hex2bin(std::string_view str, std::array<std::byte, N>& out, size_t& out_len) {
	return hex2bin(str, out.data(), N, out_len);
}

template <size_t N>
bool
hex2bin(std::string_view str, std::byte (&out)[N]) {
	size_t olen;
	if (!hex2bin(str, out, olen)) {
		return false;
	}
	if (olen != N) {
		return false;
	}
	return true;
}

template <size_t N>
bool
hex2bin(std::string_view str, std::array<std::byte, N>& out) {
	size_t olen;
	if (!hex2bin(str, out, olen)) {
		return false;
	}
	if (olen != N) {
		return false;
	}
	return true;
}

std::string bin2hex(const std::byte* data, size_t data_size, bool upper = false);
inline std::string
bin2hex(const uint8_t* data, size_t data_size, bool upper = false) {
	return bin2hex(reinterpret_cast<const std::byte*>(data), data_size, upper);
}
template <size_t N>
inline std::string
bin2hex(const std::array<std::byte, N> data, bool upper = false) {
	return bin2hex(data.data(), data.size(), upper);
}
template <size_t N>
inline std::string
bin2hex(const std::byte (&array)[N], bool upper = false) {
	return bin2hex(array, N, upper);
}
template <size_t N>
inline std::string
bin2hex(const uint8_t (&array)[N], bool upper = false) {
	return bin2hex(array, N, upper);
}
template <size_t N>
inline std::string
bin2hex(const std::array<uint8_t, N> data, bool upper = false) {
	return bin2hex(data.data(), data.size(), upper);
}
inline std::string
bin2hex(const char* data, size_t len, bool upper = false) {
	return bin2hex(reinterpret_cast<const std::byte*>(data), len, upper);
}
inline std::string
bin2hex(const std::string_view data, bool upper = false) {
	return bin2hex(reinterpret_cast<const std::byte*>(data.data()), data.size(), upper);
}

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
