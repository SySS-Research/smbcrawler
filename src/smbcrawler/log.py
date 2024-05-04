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


class DBHandler(logging.Handler):
    """
    Logging handler for a database
    """

    def __init__(self, db_queue):
        super().__init__()
        self.db_queue = db_queue

    def emit(self, record):
        data = dict(
            message=record.msg,
            level=record.levelname,
            thread_id=record.thread,
            line_no=record.lineno,
            module=record.module,
            func_name=record.funcName,
        )
        self.db_queue.write("LogItem", data)


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
        with open(self.path, 'w') as fifo:
            while True:
                record = self.log_queue.get()
                if record is None:
                    # None is used as a signal to stop the thread
                    break
                msg = self.format(record)
                fifo.write(msg + '\n')
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


def init_logger(db_queue, fifo_pipe, id_=None):
    logging.basicConfig(level=logging.DEBUG)

    logger = logging.getLogger("smbcrawler.logger_%s" % id_)
    logger.handlers = []

    # add success level
    def success(self, message, *args, **kwargs):
        self._log(logging.SUCCESS, message, args, **kwargs)

    logging.Logger.success = success

    #  try:
    #      fifo_handler = FIFOHandler(fifo_pipe)
    #      fifo_handler.setLevel("DEBUG")
    #      fifo_handler.setFormatter(CustomFormatterDebug())
    #      logger.handlers.append(fifo_handler)
    #  except Exception as e:
    #      print("Couldn't create fifo pipe: %s" % e)
    # TODO not working. revisit later

    db_handler = DBHandler(db_queue)
    logger.handlers.append(db_handler)

    return logger
