#pragma once
#include <functional>
#include <memory>
#include "BLEBackend.h"
#include "Sesame.h"

namespace libsesame3bt::core {

class SesameServerCoreImpl;

using registration_callback_t = std::function<void(const std::array<std::byte, Sesame::SECRET_SIZE>& secret)>;

class SesameServerCore {
 public:
	SesameServerCore(SesameBLEBackend& backend);
	SesameServerCore(const SesameServerCore&) = delete;
	SesameServerCore& operator=(const SesameServerCore&) = delete;
	virtual ~SesameServerCore();

	bool generate_keypair();
	bool load_key(const std::array<std::byte, Sesame::SK_SIZE>& privkey);
	bool export_keypair(std::array<std::byte, Sesame::PK_SIZE>& pubkey, std::array<std::byte, Sesame::SK_SIZE>& privkey);
	bool set_registered(const std::array<std::byte, Sesame::SECRET_SIZE>& secret);
	void begin_activation();
	void on_received(const std::byte*, size_t);
	void on_disconnected();
	void set_on_registration_callback(registration_callback_t callback);

 private:
	std::unique_ptr<SesameServerCoreImpl> impl;
};

}  // namespace libsesame3bt::core
