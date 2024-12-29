# Changelog

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
