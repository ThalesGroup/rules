from falco_mitre_checker.cli.core import cli
from falco_mitre_checker.utils.logger import MitreCheckerLogger


def main():
    # init logger
    MitreCheckerLogger()
    # init cli
    cli()


if __name__ == '__main__':
    """
    for debug purpose
    """
    main()
