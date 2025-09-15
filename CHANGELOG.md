# Changelog

## [v0.14.0] 2025-09-15
- Fix Remote, Bot2 battery voltage (was doubled)
- Support Bike 2.
- Support 2025 Aug firmware of Bot 2 / Bike 2 (lock status is supported)
- Status::motor_status() is only for SESAME bot (not Bot 2 and other devices)
- Status::stopped() is not meaningful for SESAME 3 / SESAME 4

## [v0.13.0] 2025-09-06
- Add Status::is_critical() (Reflect SESAME 5 is_critical flag)

## [v0.12.0] 2025-08-09
- Reorganize platformio.ini to build for both Arduino 3.x and 2.x.

## [v0.11.0] 2025-06-08
### Additions
- Add `uuid_to_ble_address()`, SESAME specific address conversion.
- Add `model_t` symbols (face, etc).
- Support SESAME Face / SESAME Face Pro (Battery level retrieval).

### Breaking changes
- Add `trigger_type` argument to `on_command` callback.
Support for new Sesame history tag format (May 2025).
	- If `trigger_type` has a value, the `tag` string will be a UUID (128-bit) hex string.
The human-readable tag string value appears to be managed by the SESAME Server (SESAME Biz).
	 - Touch/Remote with older firmware will send the literal tag string as before. In that case, `trigger_value` will not have a value.

## Important changes
- `struct History` has been modified to handle the new spec history in the history callback.
	- Added `trigger_type` member.
	- Maximum tag string length increased to 32 (Hexstring of UUID).
	- If `trigger_type` has a value, the `tag` string will be a UUID (128-bit) hex string.
- The tag parameter handling in `lock()`/`unlock()`/`click()` is unchanged. Specified string is passed to SESAME as is.

## [v0.10.0] 2025-05-31
- Add `has_session()` to SesameServerCore.

## [v0.9.0] 2025-02-22

- For SESAME bot (1) click(std::string_view) reverted.
- Add History member: result, record_id
- Add Status member: ret_code (valid for OS2 devices).
- Do not call history callback on corrupted responses.

## [v0.8.0] 2024-12-29

- Add Sesame Server feature

## [v0.7.0] 2024-09-14

- Support SESAME Bot 2
- Many structural changes to implement encrpyt / decrypt functionality for device side

## [v0.6.0] 2024-04-28

- Support SESAME Touch / Bike2 / Open Sensor (Tested on Touch only).
- Add `request_status()` (handled on some devices: SESAME 5 seems not handle).

## [v0.5.0] 2024-04-01

- Export some utility functions

## [v0.4.0] 2024-03-30
### Breaking changes

- remove `state_t::connected`, normal state transitions is idle -> authenticating -> active
- remove `on_connected()`

## [v0.3.0] 2024-03-24

- Make some interface accept std::string_view instead of const char *

## [v0.2.0] 2024-03-23

- Ignore duplicate "initial" packets during authentication.

## [v0.1.1] 2024-03-13

- Update README and source comment.

## [v0.1.0] 2024-03-12

### Major changes

- Extract platform independent routines from `libsesame3bt` and rename to `libsesame3bt-core`
