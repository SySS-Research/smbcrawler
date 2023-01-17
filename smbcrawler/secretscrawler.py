import logging
import json
import html
import pathlib
import urllib.parse


from .io import get_short_hash, SECRETS, find_secrets

log = logging.getLogger(__name__)


css = '''
table {
  border: 1px solid #ccc;
  border-collapse: collapse;
  margin: 0;
  padding: 0;
  /* TODO do something about column width */
  /* width: 100%; */
  table-layout: fixed;
}

table caption {
  font-size: 1.5em;
  margin: .5em 0 .75em;
}

table tr {
  background-color: #f8f8f8;
  border: 1px solid #ddd;
  padding: .35em;
}

table th,
table td {
  padding: .625em;
  text-align: center;
}

table th {
  font-size: .85em;
  letter-spacing: .1em;
  text-transform: uppercase;
}

@media screen and (max-width: 600px) {
  table {
    border: 0;
  }

  table caption {
    font-size: 1.3em;
  }

  table thead {
    border: none;
    clip: rect(0 0 0 0);
    height: 1px;
    margin: -1px;
    overflow: hidden;
    padding: 0;
    position: absolute;
    width: 1px;
  }

  table tr {
    border-bottom: 3px solid #ddd;
    display: block;
    margin-bottom: .625em;
  }

  table td {
    border-bottom: 1px solid #ddd;
    display: block;
    font-size: .8em;
    text-align: right;
  }

  table td::before {
    /*
    * aria-label has no advantage, it won't be read inside a table
    content: attr(aria-label);
    */
    content: attr(data-label);
    float: left;
    font-weight: bold;
    text-transform: uppercase;
  }

  table td:last-child {
    border-bottom: 0;
  }
}

/* general styling */
body {
  font-family: "Open Sans", sans-serif;
  line-height: 1.25;
}
'''

html_template = '''
<!DOCTYPE html>
<html>
<head>
<title>SmbCrawler</title>
<style>
%(css)s
</style>
</head>
<body>
<h1>SmbCrawler</h1>
%(table)s
</body
</html>
'''


def run(paths, output, format, recursive=False, as_json=False):
    file_map = {}
    files = []

    for p in paths:
        p = pathlib.Path(p)
        if p.is_file():
            files.append(p)
        else:
            pattern = '*'
            if recursive:
                pattern = '**/*'
            files.extend(p.glob(pattern))

    for f in files:
        if as_json:
            data = json.load(open(str(f), 'r'))
            SECRETS.update(data)
            continue
        data = open(str(f), 'rb').read()
        content_hash = get_short_hash(data)
        file_map[content_hash] = f
        try:
            find_secrets(data, f, content_hash)
        except Exception:
            log.error("Error in file: %s" % f, exc_info=True)

    create_output(output, format, SECRETS, file_map)


def create_output(output, format, secrets, file_map):
    if format == 'html':
        import json2html
        table = json2html.json2html.convert(secrets)
        for content_hash, filename in file_map.items():
            filename = urllib.parse.quote(str(filename).encode())
            filename = html.escape(filename)
            table = table.replace(
                content_hash,
                '<a href="%s" target="_blank">%s</a>'
                % (filename, content_hash),
            )
        output.write(html_template % dict(table=table, css=css))
    elif format == 'json':
        json.dump(secrets, output, indent=4)
