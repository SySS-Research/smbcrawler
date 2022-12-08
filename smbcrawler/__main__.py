import sys


def main(args=None):
    from smbcrawler.args import parse_args
    parsed_args = parse_args(args or sys.argv[1:])

    from smbcrawler.log import init_log
    init_log(parsed_args)

    cmd_args = ' '.join(args or sys.argv[1:])
    if parsed_args.password:
        cmd_args = cmd_args.replace(parsed_args.password, '***')

    from smbcrawler.app import CrawlerApp
    CrawlerApp(parsed_args, cmd=cmd_args).run()


if __name__ == "__main__":
    main()
