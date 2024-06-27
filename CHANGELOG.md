# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## SemVer public API

The [public API](https://semver.org/spec/v2.0.0.html#spec-item-1)  for this project is defined by the set of 
functions provided by the `src/cscapi` folder.

--- 

## [0.7.0](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.7.0) - 2024-06-27
[_Compare with previous release_](https://github.com/crowdsecurity/python-capi-sdk/compare/v0.6.0...v0.7.0)

### Changed

- Do not block signals sending in the event of machine failure ([#31](https://github.com/crowdsecurity/python-capi-sdk/pull/31))

---

## [0.6.0](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.6.0) - 2024-03-29
[_Compare with previous release_](https://github.com/crowdsecurity/python-capi-sdk/compare/v0.5.0...v0.6.0)

### Added

- Add MongoDB storage implementation ([#27](https://github.com/crowdsecurity/python-capi-sdk/pull/27))

---

## [0.5.0](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.5.0) - 2024-03-20
[_Compare with previous release_](https://github.com/crowdsecurity/python-capi-sdk/compare/v0.4.0...v0.5.0)

### Changed

- **Breaking change**: Add `StorageInterface::mass_update_signals` method

---

## [0.4.0](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.4.0) - 2024-02-23
[_Compare with previous release_](https://github.com/crowdsecurity/python-capi-sdk/compare/v0.3.0...v0.4.0)


### Changed

- **Breaking change**: Rename `StorageInterface::get_all_signals` to `get_signals` and add `limit`, `offset`, `sent` and `is_failing` arguments
- **Breaking change**: Change `StorageInterface::delete_signals` signature to require a list of signal ids
- **Breaking change**: Change `StorageInterface::delete_machines` signature to require a list of machine ids
- Add `batch_size` argument to `CAPIClient::send_signals` and `CAPIClient::prune_failing_machines_signals` methods
- `CAPIClient::send_signals` and `CAPIClient::prune_failing_machines_signals` now return the number of signals sent or pruned
- `CAPIClient::send_signals` and `CAPIClient::prune_failing_machines_signals` now send and prune signals in batches


### Removed

- **Breaking change**: Remove `CAPIClient::_prune_sent_signals` method


---

## [0.3.0](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.3.0) - 2024-02-16
[_Compare with previous release_](https://github.com/crowdsecurity/python-capi-sdk/compare/v0.2.1...v0.3.0)


### Changed

- Use context manager for Sql session ([#20](https://github.com/crowdsecurity/python-capi-sdk/pull/20))
- **Breaking change**: The `session` attribute of `SQLStorage` is now an instance of the [sessionmaker](https://docs.sqlalchemy.org/en/20/orm/session_api.html#sqlalchemy.orm.sessionmaker) class and should be used as such.

### Added

- Add `CAPIClientConfig` logger attribute ([#21](https://github.com/crowdsecurity/python-capi-sdk/pull/21))


---



## [0.2.1](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.2.1) - 2024-02-09
[_Compare with previous release_](https://github.com/crowdsecurity/python-capi-sdk/compare/v0.2.0...v0.2.1)


### Fixed

- Decrease `machine_id` database length to 128 characters for Mysql compatibility ([#17](https://github.com/crowdsecurity/python-capi-sdk/pull/17)) and ([#18](https://github.com/crowdsecurity/python-capi-sdk/pull/18))

---

## [0.2.0](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.2.0) - 2024-02-09
[_Compare with previous release_](https://github.com/crowdsecurity/python-capi-sdk/compare/v0.1.0...v0.2.0)


### Changed

- Update `create_signal` function to accept datetime object for the `created_at` argument ([#16](https://github.com/crowdsecurity/python-capi-sdk/pull/16))

---

## [0.1.0](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.1.0) - 2024-02-08
[_Compare with previous release_](https://github.com/crowdsecurity/python-capi-sdk/compare/v0.0.2...v0.1.0)

### Changed

- **Breaking change**: Change method name `CAPIClient::has_valid_scenarios` to `CAPIClient::_has_valid_scenarios`

### Added

- Add `CAPIClient::prune_failing_machines_signals` method for deleting signals from failing machines ([#14](https://github.com/crowdsecurity/python-capi-sdk/pull/14))


---

## [0.0.2](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.0.2) - 2024-02-07
[_Compare with previous release_](https://github.com/crowdsecurity/python-capi-sdk/compare/v0.0.1...v0.0.2)


### Fixed

- Enable foreign key constraints only in SQLite connections ([#13](https://github.com/crowdsecurity/python-capi-sdk/pull/13))

---

## [0.0.1](https://github.com/crowdsecurity/python-capi-sdk/releases/tag/v0.0.1) - 2024-02-06

- Initial release
