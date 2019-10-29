import logging


def init_log(args):
    raw_log_level = 2 + (args.verbose or 0) - (args.quiet or 0)
    if raw_log_level <= 0:
        log_level = logging.CRITICAL
    elif raw_log_level == 1:
        log_level = logging.ERROR
    elif raw_log_level == 2:     # default
        log_level = logging.WARNING
    elif raw_log_level == 3:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG

    if log_level == logging.DEBUG:
        FORMAT = '%(levelname).1s %(asctime)-15s ' \
                 '%(filename)s:%(lineno)d %(message)s'
    else:
        FORMAT = '%(levelname).1s %(asctime)-15s %(message)s'

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(logging.Formatter(
            FORMAT,
            datefmt="%Y-%m-%d %H:%M:%S",
    ))

    handlers = [stream_handler]

    if args.outputfilename_log:
        file_handler = logging.FileHandler(args.outputfilename_log)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            FORMAT,
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        handlers.append(file_handler)

    logging.basicConfig(
        level=logging.DEBUG,
    )

    logging.getLogger('').handlers = handlers
