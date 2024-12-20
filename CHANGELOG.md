# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 1.0.0 (???)

Major changes in this one.

### Changed

- Use sqlite instead of JSON files for output
- Revamped CLI
- Use profiles instead of `interesting_shares` etc. lists
- Decluttered console output
- Improved the regular expressions that find the secrets

### Added

- Interacive HTML report
- Tab completion for popular shells using the `click` library
- Detailed status update


## 0.2.0 (2022-09-23)

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
