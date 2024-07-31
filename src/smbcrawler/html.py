import json
import shutil
import tempfile
from pathlib import Path
import os

import jinja2
from zundler import embed  # type: ignore

import smbcrawler
from smbcrawler import queries

BASE_DIR = Path(os.path.abspath(os.path.dirname(smbcrawler.__file__)))


def generate_html(crawl_file: str, outputfile: str) -> None:
    tempdir = tempfile.TemporaryDirectory(
        prefix="smcrawler_html_report_",
        delete=False,
        ignore_cleanup_errors=True,
    )

    try:
        render_templates(tempdir.name)
        copy_static_files(tempdir.name, crawl_file)
        embed.embed_assets(str(Path(tempdir.name) / "index.html"), outputfile)
    finally:
        #  tempdir.cleanup()
        print(tempdir.name)


def render_templates(directory: str) -> None:
    sidebar = [
        dict(label="index", title="Summary", icon=None),
        dict(label="targets", title="Targets", icon=None),
        dict(label="shares", title="Shares", icon=None),
        dict(label="paths", title="Paths", icon=None),
        dict(label="tree", title="Tree", icon=None),
        dict(label="secrets", title="Secrets", icon=None),
    ]
    queries_json = json.dumps(queries.ALL_QUERIES)

    template_path = BASE_DIR / "assets" / "html_templates"
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_path),
    )

    for page in sidebar:
        file = f"{page['label']}.html"
        t = env.get_template(file)
        content = t.render(sidebar=sidebar, queries=queries_json)
        open(Path(directory) / file, "w").write(content)


def copy_static_files(directory: str, crawl_file) -> None:
    shutil.copytree(BASE_DIR / "assets" / "static", Path(directory) / "static")
    shutil.copy(crawl_file, Path(directory) / "static" / "crawl.sqlite")
    shutil.copytree(Path(crawl_file + ".d") / "content", Path(directory) / "content")
