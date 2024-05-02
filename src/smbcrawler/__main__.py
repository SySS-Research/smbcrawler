import sys


def main(*args, **kwargs):
    from smbcrawler.clickargs import cli
    cli(*args, **kwargs)


def main_(*args):
    from smbcrawler.args import parse_args

    if not args:
        args = sys.argv[1:]
    parsed_args = parse_args(args)

    from smbcrawler.log import init_log

    init_log(parsed_args)

    cmd_args = " ".join(args)
    if parsed_args.password:
        cmd_args = cmd_args.replace(parsed_args.password, "***")

    from smbcrawler.app import CrawlerApp

    CrawlerApp(parsed_args, cmd=cmd_args).run()


def main_secrets(args=None):
    from smbcrawler.args_secrets import parse_args

    parsed_args = parse_args(args or sys.argv[1:])

    from smbcrawler.log import init_log

    for k, v in {
        "quiet": 1,
        "verbose": 0,
        "disable_log_file": True,
        "disable_share_output": True,
        "disable_path_output": True,
    }.items():
        setattr(parsed_args, k, v)
    init_log(parsed_args)

    from smbcrawler.secretscrawler import run

    run(
        parsed_args.paths,
        parsed_args.output,
        parsed_args.format,
        recursive=parsed_args.recursive,
        as_json=parsed_args.as_json,
    )


if __name__ == "__main__":
    main()
