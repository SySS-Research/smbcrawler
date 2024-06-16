import csv
import io
import json
import logging
import sqlite3
import yaml

from smbcrawler import queries
from smbcrawler import html

logger = logging.getLogger(__name__)


def generate(crawl_file, format, outputfile, section=None):
    if format == "html":
        if section:
            logger.warn(
                "The --section argument is ignored when generating an HTML report"
            )
        html.generate_html(crawl_file, outputfile)
        return

    report = generate_report(crawl_file)

    if section:
        report = report[section]

    if format == "json":
        output = json.dumps(report)
    elif format == "yaml":
        output = yaml.dump(report)
    elif format == "csv":
        if isinstance(report, dict):
            report = [report]
        skip_header = False
        for i, line in enumerate(report):
            if not isinstance(line, dict):
                skip_header = True
                report[i] = {"value": line}

        fieldnames = report[0].keys()

        output_io = io.StringIO()
        writer = csv.DictWriter(output_io, fieldnames=fieldnames, delimiter="\t")
        if not skip_header:
            writer.writeheader()

        writer.writerows(report)
        output = output_io.getvalue()

    outputfile.write(output)


def generate_report(crawl_file):
    secrets = run_query(crawl_file, queries.secrets_with_paths)
    shares = run_query(crawl_file, "SELECT * FROM Share")
    targets = run_query(crawl_file, "SELECT * FROM Target")
    config = run_query(crawl_file, "SELECT * FROM Config")
    high_value_files = run_query(
        crawl_file,
        queries.high_value_files,
    )
    high_value_shares = run_query(
        crawl_file,
        queries.high_value_shares,
    )
    # TODO undeleted directories

    result = {
        "secrets_unique": list(set(s["secret"] for s in secrets)),
        "high_value_files": high_value_files,
        "high_value_shares": high_value_shares,
        "secrets": secrets,
        "shares": shares,
        "targets": targets,
        "config": config,
    }
    insert_summary(result)
    return result


def insert_summary(report: dict) -> None:
    summary = {
        "Total targets": len(report["targets"]),
        "Targets with open ports": sum(1 for t in report["targets"] if t["port_open"]),
        "Targets with at least one share": len(
            {s["target_id"] for s in report["shares"] if s.get("target_id")}
        ),
        "Total secrets": len(report["secrets"]),
        "Unique secrets": len(report["secrets_unique"]),
        "Total shares": len(report["shares"]),
        "Shares with listable root": sum(
            1 for s in report["shares"] if s["read_level"]
        ),
        "Shares with listable root as guest": sum(
            1 for s in report["shares"] if s["read_level"] and s["guest_access"]
        ),
        "Shares with write access in root": sum(
            1 for s in report["shares"] if s["write_access"]
        ),
        "High value files": len(report["high_value_files"]),
        "High value shares": len(report["high_value_shares"]),
    }

    report["summary"] = summary


def run_query(pathToSqliteDb: str, query: str) -> list[dict]:
    connection = sqlite3.connect(pathToSqliteDb)

    def dict_factory(curs, row):
        d = {}
        for idx, col in enumerate(curs.description):
            val = row[idx]
            if isinstance(val, bytes):
                val = val.decode()
            d[col[0]] = val
        return d

    connection.row_factory = dict_factory
    cursor = connection.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    connection.close()
    return results


def show_log(crawl_file):
    log = run_query(crawl_file, "SELECT * FROM LogItem")
    for line in log:
        msg = "{level[0]} [{timestamp}] {message}".format(**line)
        print(msg)
