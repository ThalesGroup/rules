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

Or mannualy using `pip` :

```sh
pip install dist/mitre_checker-0.1.0-py3-none-any.whl
```

## Usage

```sh
falco_mitre_checker --help
```

Example :

```sh
falco_mitre_checker -f rules/falco_rules.yaml -o /tmp/
```

## Using the container image with `podman` or `docker`

> Tested with `podman` 4.6.0, but it should be similar with `docker`

### Building the container image

```bash
podman build -f Containerfile -t localhost/falco-mitre-checker:stable
```

### Create an alias to use it in terminal

**Note**: not compatible with `fish` terminal, use `bash`.

```bash
alias falco_mitre_checker='podman run --rm --interactive        \
                          --security-opt label=disable          \
                          --volume "${PWD}":/pwd --workdir /pwd \
                          localhost/falco-mitre-checker:stable'
```

or with a more explicit alias name:

```bash
alias falco_mitre_checker_container='podman run --rm --interactive \
                          --security-opt label=disable \
                          --volume "${PWD}":/pwd --workdir /pwd \
                          localhost/falco-mitre-checker:stable'
```

Try the alias:

```bash
falco_mitre_checker_container --help
```
```
Usage: python -m falco_mitre_checker [OPTIONS]

Options:
  -f, --file PATH                 Path to a Falco rules file. Repeat for
                                  multiple files validation.  [required]
  -d, --domain TEXT               Mitre ATT&CK domain name.  [default:
                                  enterprise-attack]
  -V, --Version TEXT              Mitre ATT&CK domain version.  [default:
                                  13.1]
  -o, --output-dir PATH           Path to a directory to dump the error report
                                  for Mitre ATT&CK.
  --install-completion [bash|zsh|fish|powershell|pwsh]
                                  Install completion for the specified shell.
  --show-completion [bash|zsh|fish|powershell|pwsh]
                                  Show completion for the specified shell, to
                                  copy it or customize the installation.
  -h, --help                      Show this message and exit.
```

**TODO: Need to troubleshoot the following error**

```bash
falco_mitre_checker_container -f falco_mitre_checker/tests/resources/falco_rules_test.yaml -o .
```
```
[INFO] Load Mitre ATT&CK STIX Data for domain 'enterprise-attack' and version '13.1'
[INFO] Audit Falco rules file 'falco_mitre_checker/tests/resources/falco_rules_test.yaml' for Mitre ATT&CK
Traceback (most recent call last):

  File "/usr/local/lib/python3.10/runpy.py", line 196, in _run_module_as_main
    return _run_code(code, main_globals, None,

  File "/usr/local/lib/python3.10/runpy.py", line 86, in _run_code
    exec(code, run_globals)

  File "/pwd/falco_mitre_checker/__main__.py", line 16, in <module>
    main()

  File "/pwd/falco_mitre_checker/__main__.py", line 9, in main
    cli()

  File "/pwd/falco_mitre_checker/cli/core.py", line 38, in cli
    app()

  File "/pwd/falco_mitre_checker/cli/core.py", line 31, in core
    mitre_checker_engine(rules_files, mitre_domain, mitre_version, output_dir)

  File "/pwd/falco_mitre_checker/api/core.py", line 33, in mitre_checker_engine
    FalcoMitreChecker.dump_errors(errors, output_path)

  File "/pwd/falco_mitre_checker/engine/mitre_checker.py", line 111, in dump_errors
    write_file(FalcoRulesErrors(errors=falco_mitre_errors).json(), output)

  File "/pwd/falco_mitre_checker/utils/file.py", line 19, in write_file
    with open(os.path.expandvars(output), 'w') as f:

PermissionError: [Errno 13] Permission denied: 'falco_rules_test_mitre_errors.json'
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

Install with dependencies for development : 

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

Actual coverage report :

```
---------- coverage: platform linux, python 3.10.12-final-0 ----------      
Name                                                     Stmts   Miss  Cover
----------------------------------------------------------------------------
falco_mitre_checker/__init__.py                              0      0   100%
falco_mitre_checker/__main__.py                              7      7     0%
falco_mitre_checker/api/__init__.py                          0      0   100%
falco_mitre_checker/api/core.py                             19     19     0%
falco_mitre_checker/cli/__init__.py                          0      0   100%
falco_mitre_checker/cli/core.py                             18     18     0%
falco_mitre_checker/engine/__init__.py                       0      0   100%
falco_mitre_checker/engine/mitre_checker.py                 46      1    98%
falco_mitre_checker/exceptions/__init__.py                   0      0   100%
falco_mitre_checker/exceptions/rules_exceptions.py           8      0   100%
falco_mitre_checker/models/__init__.py                       0      0   100%
falco_mitre_checker/models/falco_mitre_errors.py            16      0   100%
falco_mitre_checker/models/falco_mitre_relations.py         14      2    86%
falco_mitre_checker/parsers/__init__.py                      0      0   100%
falco_mitre_checker/parsers/falco_rules.py                  30      1    97%
falco_mitre_checker/parsers/mitre_stix.py                   31      4    87%
falco_mitre_checker/tests/__init__.py                        0      0   100%
falco_mitre_checker/tests/engine/__init__.py                 0      0   100%
falco_mitre_checker/tests/engine/test_mitre_checker.py      41      0   100%
falco_mitre_checker/tests/parsers/__init__.py                0      0   100%
falco_mitre_checker/tests/parsers/test_falco_rules.py       18      0   100%                                                                
falco_mitre_checker/tests/parsers/test_mitre_stix.py        34      0   100%                                                                
falco_mitre_checker/tests/test_common.py                    13      2    85%                                                                
falco_mitre_checker/utils/__init__.py                        0      0   100%                                                                
falco_mitre_checker/utils/file.py                           10      0   100%                                                                
falco_mitre_checker/utils/logger.py                         36      7    81%                                                                
----------------------------------------------------------------------------                                                                
TOTAL                                                      341     61    82%
```

### Security

You should run a vulnerability scanner every time you add a new dependency in projects :

```sh
poetry run python -m safety check
```

Actual vulnerability report :

```
  Using non-commercial database
  Found and scanned 32 packages
  Timestamp 2023-08-07 10:38:45
  0 vulnerabilities found
  0 vulnerabilities ignored
+==========================================================================================================================================+

 No known security vulnerabilities found. 

+==========================================================================================================================================+
```
