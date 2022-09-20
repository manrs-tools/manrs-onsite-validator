# MANRS on-site config validator

This tool tests router configs against MANRS guidelines, specifically
traffic filtering on interfaces and prefix filtering on BGP sessions.

This tool supports all devices
[supported by Batfish](https://pybatfish.readthedocs.io/en/latest/supported_devices.html).
See that page for details of supported configuration formats.


## Usage with Docker

* Start a local Batfish service in Docker
  [per the installation instructions](https://pybatfish.readthedocs.io/en/latest/getting_started.html).
  You do not need to install the pybatfish package.
* Place your router config files in a directory somewhere, e.g.:
  `/tmp/configs/juniper1.cfg`.

Then, pull the latest Docker image from this repository, and run it, mounting
your config directory into `/snap/configs` on the container, so if your
configs are in `/tmp/configs` on the host:

* `docker pull ghcr.io/manrs-tools/manrs-onsite-validator:main`
* `docker run -v /tmp/configs:/snap/configs ghcr.io/manrs-tools/manrs-onsite-validator:main`

Any ERROR output is a suspected configuration that does not meet MANRS guidelines.
You can get additional debugging output by adding `-d` at the end.


## Running locally

You can also call `ocv/run.py` directly from a checkout of this repository,
for easier development. The only required Python package is `pybatfish`, as
listed in `requirements.txt`.


## Tests

This tool has an integration test that compares the output for the configs
`ocv/test_data/snap` to `ocv/test_data/expected_output.txt`.
