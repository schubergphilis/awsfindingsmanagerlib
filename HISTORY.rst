.. :changelog:

History
-------


0.1.0 (26-04-2024)
------------------

* Initial release.


0.1.1 (19-06-2024)
------------------

* Fix s3 backend.


0.1.2 (19-06-2024)
------------------

* Bump dependencies.


1.0.0 (26-07-2024)
------------------

* Fix event handling.


1.0.1 (02-10-2024)
------------------

* Bump template python version to 3.11.


1.0.2 (04-10-2024)
------------------

* Fix development dependencies.


1.0.3 (04-10-2024)
------------------

* Bump twine to latest version to fix upload on pipeline.


1.0.4 (14-10-2024)
------------------

* Bump template python version to 3.12.
* Bugfixes.


1.1.0 (21-11-2024)
------------------

* Adds support for SecurityHub Integration findings


1.2.0 (24-12-2024)
------------------

* Updates default SecurityHub filter to fix issues with SecurityHub Integration findings support.
* Adjusted filtering logic to align with SecurityHub filtering: When both `match_on` options: `tags` and `resource_id_regexps` are specified, they are now combined using an **AND** condition instead of an **OR** condition.
* Introduce pagesize.

1.3.0 (07-04-2025)
------------------

* Adds support for filtering findings by region.
* Bump dependencies.


1.3.1 (16-09-2025)
------------------

* chore: bump dependencies
