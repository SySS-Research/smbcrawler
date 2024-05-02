import logging
import os


grey = "\x1b[38m"
magenta = "\x1b[35m"
yellow = "\x1b[33m"
green = "\x1b[32m"
red = "\x1b[31m"
bold_red = "\x1b[31;1m"
reset = "\x1b[0m"


logging.SUCCESS = 49  # almost same as critical
logging.addLevelName(logging.SUCCESS, "SUCCESS")


def color_map(_format):
    FORMATS = {
        logging.DEBUG: magenta + _format + reset,
        logging.INFO: _format,
        logging.WARNING: yellow + _format + reset,
        logging.ERROR: red + _format + reset,
        logging.CRITICAL: bold_red + _format + reset,
        logging.SUCCESS: green + _format + reset,
    }
    return FORMATS


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors"""

    _format = "%(levelname).1s %(asctime)-15s %(message)s"

    FORMATS = color_map(_format)

    def format(self, record):
        if self.color:
            log_fmt = self.FORMATS.get(record.levelno)
        else:
            log_fmt = self._format
        formatter = logging.Formatter(log_fmt, "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

    def __init__(self, color=True):
        self.color = color
        super().__init__()


class CustomFormatterDebug(CustomFormatter):
    _format = "%(levelname).1s %(asctime)-15s " "%(filename)s:%(lineno)d %(message)s"
    FORMATS = color_map(_format)


def init_log(args):
    raw_log_level = 2 + (args.verbose or 0) - (args.quiet or 0)
    if raw_log_level <= 0:
        log_level = logging.CRITICAL
    elif raw_log_level == 1:
        log_level = logging.ERROR
    elif raw_log_level == 2:  # default
        log_level = logging.WARNING
    elif raw_log_level == 3:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)

    # create formatter and add it to the stream handler
    if log_level == logging.DEBUG:
        formatter = CustomFormatterDebug()
    else:
        formatter = CustomFormatter()
    stream_handler.setFormatter(formatter)

    handlers = [stream_handler]

    if not args.disable_log_file:
        file_handler = logging.FileHandler(
            os.path.join(
                args.output_dir,
                args.session_name + ".log",
            )
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(CustomFormatterDebug(color=False))
        handlers.append(file_handler)

    logging.basicConfig(
        level=logging.DEBUG,
    )

    logger = logging.getLogger("")
    logger.handlers = handlers

    # add success level
    def success(self, message, *args, **kwargs):
        self._log(logging.SUCCESS, message, args, **kwargs)

    logging.Logger.success = success

    # Create grep loggers
    grep_loggers = [
        [
            args.disable_share_output,
            "sharegrep_logger",
            "_shares.grep",
            "\t".join(
                [
                    "name",
                    "host",
                    "share",
                    "remark",
                    "permissions",
                ]
            ),
        ],
        [
            args.disable_path_output,
            "pathgrep_logger",
            "_paths.grep",
            "\t".join(["host", "share", "path", "size"]),
        ],
    ]
    for disabled, name, filename, header in grep_loggers:
        if disabled:
            continue
        logger = logging.getLogger(name)
        logger.propagate = False
        logger.handlers.clear()
        handler = logging.FileHandler(
            os.path.join(
                args.output_dir,
                args.session_name + filename,
            )
        )
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.info(header)
