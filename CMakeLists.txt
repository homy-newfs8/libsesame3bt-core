cmake_minimum_required(VERSION 3.16.0)

idf_component_register(SRCS
	"lib/libsesame3bt-core/ClientCore.cpp"
	"lib/libsesame3bt-core/ClientCoreImpl.cpp"
	"lib/libsesame3bt-core/crypt_ecc.cpp"
	"lib/libsesame3bt-core/crypt_random.cpp"
	"lib/libsesame3bt-core/crypt.cpp"
	"lib/libsesame3bt-core/os2_iv.cpp"
	"lib/libsesame3bt-core/os2.cpp"
	"lib/libsesame3bt-core/os3_iv.cpp"
	"lib/libsesame3bt-core/os2.cpp"
	"lib/libsesame3bt-core/scanner.cpp"
	"lib/libsesame3bt-core/ServerCore.cpp"
	"lib/libsesame3bt-core/ServerCoreImpl.cpp"
	"lib/libsesame3bt-core/transport.cpp"
	"lib/libsesame3bt-core/util.cpp"
	INCLUDE_DIRS "lib/libsesame3bt-core/include"
	PRIV_REQUIRES esp_timer mbedtls)
