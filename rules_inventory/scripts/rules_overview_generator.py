import argparse
import datetime
import os
import sys
from pathlib import Path
from typing import List, Dict

import pandas as pd
import yaml

from falco_mitre_checker.api.core import mitre_checker_engine
from falco_mitre_checker.models.falco_mitre_errors import FalcoMitreError

"""
Usage:
python rules_inventory/scripts/rules_overview_generator.py --rules_file=rules/falco_rules.yaml
"""

BASE_MITRE_URL_TECHNIQUE = "https://attack.mitre.org/techniques/"
BASE_MITRE_URL_TACTIC = "https://attack.mitre.org/tactics/"
COLUMNS = ['rule', 'desc', 'workload', 'mitre_phase', 'mitre_ttp', 'extra_tags', 'extra_tags_list',
           'mitre_phase_list', 'mitre_ttp_list', 'enabled']
RULES_INVENTORY_PATH = os.path.dirname(os.path.dirname(__file__))
MITRE_VERSION = "13.1"
MITRE_DOMAIN = "enterprise-attack"


def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules_file', '--rules-file', '-f', action='store', dest='rules_file',
                        help='Path to falco rules yaml file')
    parser.add_argument('--mitre-check', action='store_true', dest='mitre', default=False,
                        help='Enable the verification of the extra tags in the rules for Mitre ATT&CK')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def write_overview(output: Path, content_lines: List[str]):
    with open(output, 'w') as f:
        for line in content_lines:
            f.write(line)


def mitre_attack_validation(rules_file: Path) -> Dict[str, List[FalcoMitreError]]:
    print("Checking for errors against the Mitre ATT&CK Framework data")
    errors_reports = mitre_checker_engine([rules_file],
                                          MITRE_DOMAIN,
                                          MITRE_VERSION,
                                          None)
    for report_name, report_values in errors_reports.items():
        print(f"Found {len(report_values)} errors in {rules_file}")

    return errors_reports


def rules_to_df(rules_file: Path):
    l = []
    with open(rules_file, 'r') as f:
        items = yaml.safe_load(f)
        for item in items:
            if 'rule' in item and 'tags' in item:
                if len(item['tags']) > 0:
                    item['workload'], item['mitre_phase'], item['mitre_ttp'], item[
                        'extra_tags'] = [], [], [], []
                    for i in item['tags']:
                        if i in ['host', 'container']:
                            item['workload'].append(i)
                        elif i.startswith('mitre'):
                            item['mitre_phase'].append(i)
                        elif i.startswith('T'):
                            if i.startswith('TA'):
                                item['mitre_ttp'].append(
                                    '[{}]({}{})'.format(i, BASE_MITRE_URL_TACTIC, i.replace('.', '/')))
                            else:
                                item['mitre_ttp'].append('[{}]({}{})'.format(i, BASE_MITRE_URL_TECHNIQUE,
                                                                             i.replace('.', '/')))
                        else:
                            item['extra_tags'].append(i)
                    item['workload'].sort()
                    item['mitre_phase'].sort()
                    item['mitre_ttp'].sort()
                    item['mitre_phase_list'] = item['mitre_phase']
                    item['mitre_ttp_list'] = item['mitre_ttp']
                    item['extra_tags_list'] = item['extra_tags']
                    item['enabled'] = (item['enabled'] if 'enabled' in item else True)
                    l.append([', '.join(item[x]) if x in ['workload', 'mitre_ttp', 'extra_tags',
                                                          'mitre_phase'] else item[x] for x in COLUMNS])
        df = pd.DataFrame.from_records(l, columns=COLUMNS)
    return df.sort_values(by=['workload', 'rule'], inplace=False)


def mitre_errors_to_df(rules_file: Path):
    mitre_errors = mitre_attack_validation(rules_file)[rules_file.stem]
    df_mitre_errors = pd.DataFrame([dict(s) for s in mitre_errors])
    return df_mitre_errors


def join_column_list(df_mitre_errors_column):
    return df_mitre_errors_column.map(lambda tactics: str.join(', ', tactics))


def build_overview(df, df_mitre_errors=None) -> "List[str]":
    n_rules = len(df)

    # percentage per workload
    df_stats1 = df.groupby('workload').agg(rule_count=('workload', 'count'))
    df_stats1['percentage'] = round(100.0 * df_stats1['rule_count'] / df_stats1['rule_count'].sum(),
                                    2).astype(str) + '%'

    # percentage per extra tag
    df_stats2 = df[['rule', 'extra_tags_list']].explode('extra_tags_list')
    df_stats2.rename(columns={'extra_tags_list': 'extra_tag'}, inplace=True)
    df_stats2 = df_stats2.groupby('extra_tag').agg(rule_count=('extra_tag', 'count'))
    df_stats2['percentage'] = round(100.0 * df_stats2['rule_count'] / df_stats2['rule_count'].sum(),
                                    2).astype(str) + '%'

    # percentage per Mitre ATT&CK phase
    df_stats3 = df[['rule', 'mitre_phase_list']].explode('mitre_phase_list')
    df_stats3.rename(columns={'mitre_phase_list': 'mitre_phase'}, inplace=True)
    df_stats3.sort_values(by=['mitre_phase', 'rule'], inplace=True)
    df_stats3 = df_stats3.groupby("mitre_phase").agg(
        {"rule": lambda x: ['\n'.join(list(x)), len(list(x))]})
    df_stats3['rules'] = df_stats3['rule'].apply(lambda x: x[0])
    df_stats3['percentage'] = df_stats3['rule'].apply(
        lambda x: round((100.0 * x[1] / n_rules), 2)).astype(str) + '%'

    # Mitre ATT&CK details overview
    df_stats4 = df.drop(['extra_tags_list', 'mitre_phase_list'], axis=1)
    df_enabled = df_stats4[(df_stats4['enabled'] == True)].drop(['enabled'], axis=1)
    df_disabled = df_stats4[(df_stats4['enabled'] == False)].drop(['enabled'], axis=1)

    # write the overview
    built_overview = [
        '# Falco Rules - Summary Stats\n\n',
        'This document is auto-generated. Last Updated: {}.\n\n'.format(datetime.date.today()),
        'The Falco project ships with [{} default rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml) around Linux syscalls and container events that were contributed by the community.\n\n'.format(
            n_rules),
        'The intended outcome of this document is to provide a comprehensive overview of the default rules, provide additional resources and help drive future improvements.\n\n',
        'Falco default rules per workload type:\n\n',
        df_stats1.to_markdown(index=True),
        '\n\nFalco default rules per [Falco tag](https://falco.org/docs/rules/#tags):\n\n',
        df_stats2.to_markdown(index=True),
        '\n\n## Falco Rules - Mitre ATT&CK overview\n\n',
        'Falco default rules per [Mitre Attack](https://attack.mitre.org/) phase:\n\n',
        df_stats3.drop('rule', axis=1).to_markdown(index=True),
        '\n\n## Falco Rules - Detailed Overview\n\n',
        '{} Falco rules ({:.2f}% of rules) are enabled by default:\n\n'.format(len(df_enabled), (
                100.0 * len(df_enabled) / n_rules)),
        df_enabled.to_markdown(index=False),
        '\n\n{} Falco rules ({:.2f}% of rules) are *not* enabled by default:\n\n'.format(
            len(df_disabled), (100.0 * len(df_disabled) / n_rules)),
        df_disabled.to_markdown(index=False)
    ]

    # mitre errors
    if df_mitre_errors is not None and not df_mitre_errors.empty:
        df_mitre_errors['tactics_tags'] = join_column_list(df_mitre_errors['tactics_tags'])
        df_mitre_errors['techniques_tags'] = join_column_list(df_mitre_errors['techniques_tags'])
        df_mitre_errors['mitre_tactics_names'] = join_column_list(df_mitre_errors['mitre_tactics_names'])
        df_mitre_errors['mitre_techniques_urls'] = join_column_list(
            df_mitre_errors['mitre_techniques_urls'])
        df_mitre_errors['reasons'] = df_mitre_errors['reasons'].map(lambda reasons: [r.value for r in reasons])
        df_mitre_errors['reasons'] = join_column_list(df_mitre_errors['reasons'])
        df_mitre_errors.rename(columns={'tactics_tags': 'rule_tactics_tags'}, inplace=True)
        df_mitre_errors.rename(columns={'techniques_tags': 'rule_techniques_tags'}, inplace=True)
        df_mitre_errors.rename(columns={'mitre_tactics_names': 'correct_mitre_tactics_names'},
                               inplace=True)
        df_mitre_errors.rename(columns={'mitre_techniques_urls': 'url'}, inplace=True)
        df_mitre_errors.rename(columns={'reasons': 'reason'}, inplace=True)
        df_mitre_errors = df_mitre_errors.drop(['mitre_techniques_names'], axis=1)

        built_overview = built_overview + [
            '\n\n## Falco Rules - Mitre ATT&CK errors\n\n',
            'Falco rules containing wrong extra tags that concern the Mitre ATT&CK framework.\n\n',
            'This table shows the proper tactics names for each Mitre technique or sub-technique.\n\n',
            f"Found {len(df_mitre_errors)} errors :\n\n",
            df_mitre_errors.to_markdown(index=False),
        ]

    return built_overview


if __name__ == "__main__":
    args_parsed = arg_parser()

    rules_path = Path(args_parsed.rules_file)
    # parse data
    df_rules = rules_to_df(rules_path)
    df_errors = mitre_errors_to_df(rules_path) if args_parsed.mitre else None
    # build the overview
    overview = build_overview(df_rules, df_errors)
    write_overview(Path(RULES_INVENTORY_PATH) / "auto_rules_overview.md", overview)
    print(f"Overview written in {Path(RULES_INVENTORY_PATH)}/auto_rules_overview.md")
