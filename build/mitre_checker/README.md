# Mitre Checker Module

The Mitre Checker module aims to check the compliance of the Falco rules against the Mitre ATT&CK
Framework. This module provides to Falco experts and Falco users a way to check default and custom
rules for Mitre ATT&CK extra tags.
This module uses STIX from the OASIS standards. Structured Threat Information Expression (STIX™) is a
language and serialization format used to exchange cyber threat intelligence (CTI) :

- [STIX CTI documentation](https://oasis-open.github.io/cti-documentation/stix/intro)

Leveraging STIX, Mitre Checker fetches the ATT&CK® STIX Data from MITRE ATT&CK repositories using the
`python-stix2` library implemented by OASIS:

- [ATT&CK STIX Data repository](https://github.com/mitre-attack/attack-stix-data)
- [Python STIX2 repository](https://github.com/oasis-open/cti-python-stix2)

The choice of a module is motivated by the packaging of a python code to integrate it into wider Falco
implementations. More precisely, the module can be used :

- by the rules_overview_generator.py script
- by Falco users and experts to check their Falco rules files
- by other Falco components that need to check the validity of rules files

## Install

Requirements :

- Python >= `3.10`

```sh
./install.sh
```

Or manualy using `pip` :

```sh
pip install dist/mitre_checker-0.1.0-py3-none-any.whl
```

## Usage

```sh
falco-mitre-checker --help
```

## Build

Requirements :

- Python >= `3.10`
- Poetry >= `1.5.1`

```sh
./build.sh
./install.sh
```

## Development

Requirements :

- Python >= `3.10`
- Poetry >= `1.5.1`

```sh
poetry check
poetry update
poetry install --sync
```

### Testing

With coverage :

```sh
poetry run python -m pytest falco_mitre_checker/tests --cov=falco_mitre_checker
```

### Security

You should run a vulnerability scanner every time you add a new dependency in projects :

```sh
poetry run python -m safety check
```
