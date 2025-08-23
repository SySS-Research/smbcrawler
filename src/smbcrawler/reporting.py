from collections import defaultdict
import csv
import io
import json
import logging
import yaml

from smbcrawler import queries
from smbcrawler import html
from smbcrawler.sql import run_query

from typing import Any

logger = logging.getLogger(__name__)


def generate(crawl_file, format, outputfile, section=None) -> None:
    if format == "html":
        if section:
            logger.warn(
                "The --section argument is ignored when generating an HTML report"
            )
        html.generate_html(crawl_file, outputfile)
        return

    report = generate_report(crawl_file, section)

    if format == "json":
        output = json.dumps(report)
    elif format == "yaml":
        output = yaml.dump(report)
    elif format == "csv":
        if isinstance(report, dict):
            report_ = [report]
        else:
            report_ = report
        skip_header = False
        for i, line in enumerate(report_):
            if not isinstance(line, dict):
                skip_header = True
                report_[i] = {"value": line}

        fieldnames = report_[0].keys()

        output_io = io.StringIO()
        writer = csv.DictWriter(output_io, fieldnames=fieldnames, delimiter="\t")
        if not skip_header:
            writer.writeheader()

        writer.writerows(report_)
        output = output_io.getvalue()

    outputfile.write(output)


def generate_report(crawl_file: str, section: str) -> list[Any]:
    # TODO undeleted directories

    queries_ = dict(queries.ALL_QUERIES)

    queries_.update(
        dict(
            shares="SELECT * FROM Share ORDER BY target_id",
            targets="SELECT * FROM Target ORDER BY name",
            config="SELECT * FROM Config",
        )
    )

    if section == "secrets":
        result = run_query(crawl_file, queries_["secrets_with_paths"])
    elif section == "secrets_cleanup_guide":
        result = run_query(crawl_file, queries_["secrets_with_paths"])
        result = create_cleanup_guide(result)
    else:
        result = run_query(crawl_file, queries_[section])

    if section == "summary":
        result = format_summary(result)  # type: ignore
    elif section == "secrets_unique":
        result = [s["secret"] for s in result]

    return result


def format_summary(summary: list[dict]) -> dict:
    labels = dict(
        number_targets="Total targets",
        number_targets_with_open_ports="Targets with open ports",
        number_targets_with_open_shares="Targets with at least one share",
        number_secrets="Total secrets",
        number_unique_secrets="Unique secrets",
        number_shares="Total shares",
        number_shares_listable_root="Shares with listable root",
        number_shares_listable_root_as_guest="Shares with listable root as guest",
        number_shares_writable="Shares with write access in root",
        number_paths="Total paths",
        number_high_value_files="High value files",
        number_high_value_shares="High value shares",
    )

    result = {labels.get(row["key"], row["key"]): row["value"] for row in summary}
    return result


def create_cleanup_guide(secrets: list[dict]) -> list[dict]:
    # Group by line first, then group by the groups

    secret_map = defaultdict(list)
    path_map = defaultdict(list)

    for s in secrets:
        secret_map[(s["secret"], s["line"], s["line_number"])].append(
            f"\\\\{s['target_name']}\\{s['share_name']}\\{s['path']}"
        )

    for k, v in secret_map.items():
        path_map[frozenset(v)].append(k)

    result = [
        {
            "secrets": [{"secret": s[0], "line": s[1], "line_number": s[2]} for s in k],
            "locations": v,
        }
        for k, v in zip(path_map.values(), map(list, path_map.keys()))
    ]

    return result


def show_log(crawl_file: str) -> None:
    log = run_query(crawl_file, "SELECT * FROM LogItem")
    for line in log:
        msg = "{level[0]} [{timestamp}] {message}".format(**line)
        print(msg)
