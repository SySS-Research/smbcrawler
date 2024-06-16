import json
import shutil
import tempfile
from pathlib import Path
import os

import jinja2
import zundler

import smbcrawler


def generate_html(crawl_file, outputfile) -> None:
    tempdir = tempfile.TemporaryDirectory(
        prefix="smcrawler_html_report_", delete=False, ignore_cleanup_errors=True
    )

    try:
        render_templates(tempdir)
        copy_static_files(tempdir, crawl_file)
        zundler.embed(Path(tempdir) / "index.html", outputfile)
    finally:
        tempdir.cleanup()


def render_templates(directory: str) -> None:
    sidebar = [
        dict(href="index", title="Summary", icon=None),
        dict(href="targets", title="Targets", icon=None),
        dict(href="shares", title="Shares", icon=None),
        dict(href="paths", title="Paths", icon=None),
        dict(href="tree", title="Tree", icon=None),
        dict(href="secrets", title="Secrets", icon=None),
    ]
    queries_json = json.dumps(smbcrawler.queries)

    env = jinja2.Environment(
        loader=jinja2.PackageLoader("smbcrawler"),
    )

    for page in sidebar:
        t = env.get_template(f"assets/html_templates/{page}.html")
        content = t.render(sidebar=sidebar, queries=queries_json)
        open(Path(directory) / f"{page}.html", "w").write(content)


def copy_static_files(directory: str, crawl_file) -> None:
    package_path = Path(os.path.abspath(smbcrawler.__file__))
    shutil.copytree(package_path / "assets" / "static", directory)
    shutil.copy(crawl_file, Path(directory) / "static")
    shutil.copy(Path(crawl_file + ".d") / "content", Path(directory))
