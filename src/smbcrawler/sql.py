import peewee
import datetime
from collections import namedtuple
import queue
import threading

from smbcrawler.args import __version__

DbInstance = namedtuple("DbInstance", "database models")


def init_db(path):
    database_instance = peewee.SqliteDatabase(path)

    class BaseModel(peewee.Model):
        class Meta:
            database = database_instance

    class Config(BaseModel):
        smbcrawler_version = peewee.CharField()
        created = peewee.DateTimeField()
        cmd = peewee.CharField()

    class Target(BaseModel):
        name = peewee.CharField(unique=True, index=True)

    class Host(BaseModel):
        name = peewee.CharField(unique=True, index=True)
        port = peewee.IntegerField(default=445)

    class Share(BaseModel):
        host = peewee.ForeignKeyField(Host, backref="shares")
        name = peewee.CharField(index=True)
        remark = peewee.CharField(default=None, null=True)

        auth_access = peewee.BooleanField()
        guest_access = peewee.BooleanField()
        write_access = peewee.BooleanField()
        read_level = peewee.IntegerField(default=-1, null=True)
        maxed_out = peewee.BooleanField(null=True)

    class FileContents(BaseModel):
        content = peewee.BlobField(unique=True, index=True)
        clean_content = peewee.TextField(null=True)

    class Path(BaseModel):
        name = peewee.CharField(index=True)
        share = peewee.ForeignKeyField(Share, backref="paths")
        size = peewee.IntegerField()
        content = peewee.ForeignKeyField(FileContents, backref="paths", null=True)

    class Event(BaseModel):
        timestamp = peewee.DateTimeField(default=datetime.datetime.now)
        message = peewee.CharField()
        event_type = peewee.CharField(
            choices={
                "error": "Error",
                "info": "info",
                "warning": "warning",
            },
        )
        path = peewee.ForeignKeyField(Path, backref="events", null=True)
        share = peewee.ForeignKeyField(Share, backref="events", null=True)
        host = peewee.ForeignKeyField(Host, backref="events", null=True)

    class Finding(BaseModel):
        certainty = peewee.CharField(
            choices={
                "certain": "Certain",
                "firm": "Firm",
                "tentative": "Tentative",
            },
        )

    class Secret(Finding):
        content = peewee.ForeignKeyField(FileContents, backref="finding_secrets")
        line = peewee.CharField()
        secret = peewee.CharField()

    class ReadableHighValueShare(Finding):
        share = peewee.ForeignKeyField(Share, backref="finding_readable_high_value_shares")

    class WritableHighValueShare(Finding):
        share = peewee.ForeignKeyField(Share, backref="finding_writeable_high_value_shares")

    class GuestAccess(Finding):
        share = peewee.ForeignKeyField(Share, backref="finding_guest_access")

    class LogItem(BaseModel):
        timestamp = peewee.DateTimeField(default=datetime.datetime.now)
        message = peewee.CharField()
        level = peewee.CharField()
        thread_id = peewee.IntegerField()
        line_no = peewee.IntegerField()
        module = peewee.CharField()
        func_name = peewee.CharField()

    models = BaseModel.__subclasses__()

    with database_instance:
        database_instance.create_tables(models)

    models = {m.__name__: m for m in models}

    # TODO check for present row in Config. offer to resume scan.

    db_instance = DbInstance(database_instance, models)

    insert_rows(
        db_instance,
        [
            (
                "Config",
                {
                    "smbcrawler_version": __version__,
                    "created": datetime.datetime.now(),
                    "cmd": "TODO",
                },
            )
        ],
    )

    return db_instance


def replace_foreign_keys(models, row):
    """Replace strings that represent a foreign relationship with the
    respective object"""

    if row[0] == "event":
        m = models["Host"]
        host = row[1]["host"]
        if host:
            row[1]["host"] = m.get(m.name == host)

        m = models["Share"]
        share = row[1]["share"]
        if host and share:
            row[1]["share"] = m.get(m.host == host & m.name == share)

        m = models["Path"]
        path = row[1]["path"]
        if host and share and path:
            row[1]["path"] = m.get(m.host == host & m.share == share & m.name == path)


def insert_rows(db_instance, rows):
    database = db_instance.database
    models = db_instance.models

    # Ensure parent objects exist when inserting objects with foreign
    # relationships
    order = list(db_instance.models.keys())
    rows_sorted = sorted(rows, key=lambda item: order.index(item[0]))

    with database.atomic():
        for row in rows_sorted:
            model = models[row[0]]
            data = row[1]

            replace_foreign_keys(models, row)

            model.create(**data)


class QueuedDBWriter:
    DONE = object()

    def __init__(self, db_instance, batch_size=100):
        self.db_instance = db_instance
        self.batch_size = batch_size
        self._batch = []

        self.queue = queue.Queue()
        self.finished = threading.Event()
        self.thread = threading.Thread(target=self._consumer)
        self.thread.start()

    def write(self, table, data):
        self.queue.put((table, data))

    def _consumer(self):
        while not self.finished.is_set() or not self.queue.empty():
            data = self.queue.get()

            if data == self.DONE:
                break

            self._batch.append(data)

            if len(self._batch) >= self.batch_size:
                self._commit()

            self.queue.task_done()

        if self._batch:
            self._commit()

    def _commit(self):
        insert_rows(self.db_instance, self._batch)
        self._batch = []

    def close(self, force=False):
        try:
            self._commit()
        finally:
            if not self.finished.is_set():
                self.finished.set()
                self.queue.put_nowait(self.DONE)
                self.thread.join()
