# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2021-09-28
### Changed
- Neuron address derivation is now supported by /construction/derive endpoint.
  Custom /neuron/derive endpoint is removed.
- /construction/submit endpoint now returns the list of operation statuses in metadata as described in the documentation.
  If there was a TRANSACTION operation in the list, the submit result will contain the hash of the corresponding ledger transfer.
  Otherwise, if all the actions are neuron-management actions, the transaction hash is all zero hash.
- "sqlite" is the default storage type now.
  Other storage types are deprecated.
- Block synchronization speed is significantly improved (~10x).
- /transaction/search endpoint now supports returning multiple transactions if the search criteria is empty.
  This enables clients to display the list of recent transactions in an efficient way.

## [1.1.0] - 2021-08-04
### Added
- Documentation for fund staking and neuron management (see `rosetta-api/docs`).
- Support for neuron management operations:
  * `SET_DISSOLVE_TIMESTAMP`
  * `START_DISSOLVING`
  * `STOP_DISSOLVING`

### Changed
- Neuron address is now supposed to be derived using a custom `/neuron/derive` endpoint.
  This is a temporary experimental feature, the next release won't contain this endpoint.

## [1.0.5] - 2021-07-22
### Added
- Support for fund staking (`STAKE` operation).
- Support for neuron address derivation.
- Sqlite storage backend.

### Changed
- BREAKING CHANGE: the internal encoding of transactions changed to support multi-step transactions (e.g., fund staking).
  Any transactions constructed with earlier versions of rosetta node cannot be applied by this version.
   

## [1.0.2] - 2020-12-10
### Added
- Original release.
