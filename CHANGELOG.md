# Changelog

ALTRepo Uploader changelog

## [newrelease] - yyyy-mm-dd

### Added
### Changed
### Fixed

## [2.3.0] - 2022-06-06

Prepared ALTRepo Uploader for distribution as RPM package.

Loading tools binaries available as shell commands if installed from RPM package.

Added `uploaderd` service that operates with RabbitMQ message broker in order to upload data to DB.

### Added
- uploaderd service binary and Systemd uinit file
- task_loader service
### Changed
- changed loading tools binary names and locations
- changed logging facility:
    - service stores logs in `/var/log/altrepodb/altrepodb.log` and system journal
    - command line tools stores log files in `/home/%user%/altrepodb/` directory
### Fixed
- project code style sanitized using `black` and `flake8` tools

## [v2.2.4] - 2022-04-15

Initial ALTRepo Uploader changelog record.

Check Git history for previous changes.

### Added
- README.md
- CHANGELOG.md
- BranchPackageHistory table and MV (triggered at TaskState)
- spdx_loader utility
### Changed
- move AUTHORS to AUTHORS.txt
- task_loader: fix argument naming and description
- added tplan_arch in task_plan_hashes view
- image_loader: add date format description
- iso_loader: add date format description
### Fixed
- iso_loader: extra package's archs from files for SquashFS components
- image_loader: fix naming
- project description wording in LICENSE file
