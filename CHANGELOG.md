# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-03-XX

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
