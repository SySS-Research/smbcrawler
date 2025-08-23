# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-08-23

### Changed

* Do not load profile files under the current working directory (#5)
* Clarify README regarding permissions check in the section "Typical workflow"

### Fixed

* Handle invalid profile files better (#5)
* Improve output of dry run (#8)
* Fix bug when using `--extra-profile-directory` (#7)

## [1.1.1] - 2025-03-21

### Fixed

* Conversion to text if optional `markitdown` dependency was missing

## [1.1.0] - 2025-02-28

### Added

- Conversion of binary files using [markitdown](https://github.com/microsoft/markitdow) if this optional dependency is present
- Useful queries have been added as views to the sqlite database
- Profile files can now also end in `*.yaml`
- Option to skip default profiles

### Removed

- The `pdftotext` dependency

### Changed

- Regular expressions in context of the profiles are now case insensitive

### Fixed
- Lots of small things
