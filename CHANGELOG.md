# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- Support for JSON and XML output files

### Changed

- Colored log output to console
- Improved multithreading
- Avoid re-downloading identical files
- Changed output file naming scheme (session name as base name instead of
  individual file names)

### Added

- Automatic detection of secrets in downloaded files
- Additional log files for secrets, files and shares, respectively
