import logging
import os
import queue
import threading


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


class ColoredFormatter(logging.Formatter):
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


class SMBFormatter(ColoredFormatter):
    def format(self, record):
        target = getattr(record, "target", None)
        share = getattr(record, "share", None)
        path = getattr(record, "path", None)
        if target:
            target = f"\\\\{target}"
            if share:
                target += f"\\{share}"
                if path:
                    target += f"\\{path}"
            record.msg = f"[{target}] {record.msg}"
            # TODO try not to modify record, as this affects other handlers
        return super().format(record)


class ColoredFormatterDebug(ColoredFormatter):
    _format = "%(levelname).1s %(asctime)-15s %(filename)s:%(lineno)d %(message)s"
    FORMATS = color_map(_format)


class DBHandler(logging.Handler):
    """
    Logging handler for a database
    """

    from smbcrawler.sql import DbInsert

    def __init__(self, db_queue):
        super().__init__()
        self.db_queue = db_queue

    def emit(self, record):
        data = dict(
            message=record.msg,
            level=record.levelname,
            thread_id=record.thread,
            line_number=record.lineno,
            module=record.module,
            exc_info=record.exc_info,
            target=str(getattr(record, "target", None)),
            share=str(getattr(record, "share", None)),
            path=str(getattr(record, "path", None)),
        )
        self.db_queue.write(self.DbInsert("LogItem", data))


class FIFOHandler(logging.Handler):
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.log_queue = queue.Queue()
        self.thread = threading.Thread(target=self.process_queue)
        self.thread.daemon = True
        self.thread.start()

    def process_queue(self):
        # Open the FIFO and keep it open
        with open(self.path, "w") as fifo:
            while True:
                record = self.log_queue.get()
                if record is None:
                    # None is used as a signal to stop the thread
                    break
                msg = self.format(record)
                # TODO include thread id in format
                fifo.write(msg + "\n")
                fifo.flush()

    def emit(self, record):
        try:
            self.log_queue.put(record)
        except Exception:
            self.handleError(record)

    def close(self):
        super().close()
        self.log_queue.put(None)  # Signal to stop the thread
        self.thread.join()
        try:
            os.unlink(self.path)
        except Exception:
            pass


def init_db_logger(db_queue):
    logger = logging.getLogger("smbcrawler")
    db_handler = DBHandler(db_queue)
    db_handler.setLevel(logging.INFO)
    logger.handlers.append(db_handler)


def init_logger(log_level=logging.WARNING):
    #  root_logger = logging.getLogger()
    logger = logging.getLogger("smbcrawler")
    logger.handlers = []
    logger.setLevel(log_level)

    # add success level
    def success(self, message, *args, **kwargs):
        self._log(logging.SUCCESS, message, args, **kwargs)

    logging.Logger.success = success

    # TODO not working. revisit later
    #  fifo_handler = FIFOHandler(fifo_pipe)
    #  fifo_handler.setLevel(logging.DEBUG)
    #  fifo_handler.setFormatter(ColoredFormatterDebug())
    #  logger.handlers.append(fifo_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(SMBFormatter())
    logger.handlers.append(console_handler)

    return logger
