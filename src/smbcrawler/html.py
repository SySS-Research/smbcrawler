import json
import shutil
import tempfile
from pathlib import Path
import os

import jinja2
from zundler import embed  # type: ignore

import smbcrawler
from smbcrawler import queries
from smbcrawler.sql import run_query

BASE_DIR = Path(os.path.abspath(os.path.dirname(smbcrawler.__file__)))


def generate_html(crawl_file: str, outputfile: str) -> None:
    tempdir = tempfile.TemporaryDirectory(
        prefix="smcrawler_html_report_",
        ignore_cleanup_errors=True,
    )

    try:
        rows = run_query(crawl_file, "SELECT DISTINCT content_hash FROM Secret")
        content_files = [r["content_hash"] for r in rows]

        render_templates(tempdir.name)
        copy_static_files(tempdir.name, crawl_file, content_files)
        embed.embed_assets(str(Path(tempdir.name) / "index.html"), outputfile)
    finally:
        tempdir.cleanup()


def render_templates(directory: str) -> None:
    base_js = ["common", "bootstrap.bundle.min", "sql-wasm.min"]
    base_css = ["bootstrap.min", "bootstrap-icons.min"]
    table_js = base_js + ["gridjs.production.min"]
    table_css = base_css + ["mermaid.min"]
    pages = [
        dict(label="index", title="Summary", icon=None, css=base_css, js=base_js),
        dict(label="targets", title="Targets", icon=None, css=table_css, js=table_js),
        dict(label="shares", title="Shares", icon=None, css=table_css, js=table_js),
        dict(label="paths", title="Paths", icon=None, css=table_css, js=table_js),
        dict(
            label="tree",
            title="Tree",
            icon=None,
            css=base_css + ["tree"],
            js=base_js + ["tree"],
        ),
        dict(label="secrets", title="Secrets", icon=None, css=table_css, js=table_js),
        dict(
            label="secrets_cleanup_guide",
            title="Secrets Cleanup Guide",
            icon=None,
            css=base_css,
            js=base_js + ["secrets_cleanup_guide"],
        ),
        dict(label="info", title="Info", icon=None, css=base_css, js=base_js),
    ]
    queries_json = json.dumps(queries.ALL_QUERIES)

    template_path = BASE_DIR / "assets" / "html_templates"
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_path),
    )

    for page in pages:
        file = f"{page['label']}.html"
        t = env.get_template(file)
        content = t.render(
            pages=pages, queries=queries_json, css=page["css"], js=page["js"]
        )
        open(Path(directory) / file, "w").write(content)


def copy_static_files(
    directory: str, crawl_file: str, content_files: list[str]
) -> None:
    shutil.copytree(BASE_DIR / "assets" / "static", Path(directory) / "static")
    shutil.copy(crawl_file, Path(directory) / "static" / "crawl.sqlite")

    # Copy content files which contain a secret
    os.makedirs(Path(directory) / "content", exist_ok=True)
    for c in content_files:
        path = Path(crawl_file + ".d") / "content" / c
        clean_path = Path(str(path) + ".txt")
        if clean_path.exists():
            path = clean_path
        shutil.copy(path, Path(directory) / "content")
