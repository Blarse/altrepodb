# Changelog

ALTRepo Uploader changelog

## [newrelease] - yyyy-mm-dd

### Added
### Changed
### Fixed

## [2.3.13] - 2022-08-10

Added ALTRepo Uploader Telegram bot service.

### Added
- Telegram bot service declares and consumes notifier service queue.
### Changed
- AMQP client class declares exchange if not exists on publish
### Fixed

## [2.3.12] - 2022-08-09

AMQP queues management transferred from server to service side.

### Added
- AMQP queues binding/unbinding in BlockingAMQPClient
### Changed
- services configuration example files updated
### Fixed

## [2.3.11] - 2022-08-04
Regular code update and fix.

### Added
### Changed
- task_service: service configuration file
### Fixed
- task_service: archived DONE tasks loading

## [2.3.10] - 2022-08-03
Regular code update and fix.

### Added
### Changed
- task_service: service configuration file
- task_loader: extended logging
### Fixed
- task_service: EPERM tasks inconsistent plan from Girar

## [2.3.9] - 2022-07-11
Regular code update and fix.

### Added
- iso_loader: verbose console printout
- image_loader: verbose console printout
### Changed
### Fixed
- type hints

## [2.3.8] - 2022-07-04
Regular code update and fix.

### Added
### Changed
- renamed worker sentinel object constant
### Fixed
- updated README.md
- updated CHANGELOG.md

## [2.3.7] - 2022-06-30
Regular code update and fix.

### Added
### Changed
- Bugzilla table structure
- bugzilla_service for new SQL tables structure 
### Fixed
- logging wording

## [2.3.6] - 2022-06-29
Regular code update and fix.

### Added
- added service base class that supports batch AMQP message processing
### Changed
- task_loader now uses batched AMQP message processing
### Fixed
- exceptions logging in services

## [2.3.5] - 2022-06-28
Regular code update and fix.

### Added
- added bugzilla_loader service
### Changed
- updated Bugzilla table structure
### Fixed
- acl_loader service errors and worker process name

## [2.3.4] - 2022-06-23
Regular code update and fix.

### Added
- added acl_loader service
### Changed
### Fixed

## [2.3.3] - 2022-06-22
Refactored ALTRepo Uploader code.

### Added
- repodb_amqfire utility to send AMQP messages to uploaderd services
- dependency to rabbitmq-c package
### Changed
- set service process and worker names
### Fixed
- logging levels and wording

## [2.3.1] - 2022-06-16
Refactored uploaderd services code to use processes instead of threads.

### Added
### Changed
- using processes instead of threads for service instances
- using simple blocking AMQP client
### Fixed
- uploaderd zombie and orphaned processes when service stopped/restarted

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
