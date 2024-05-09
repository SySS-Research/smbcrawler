import functools
import datetime
from collections import namedtuple
import queue
import threading

import peewee

from smbcrawler.args import __version__

DbInstance = namedtuple("DbInstance", "database models")


def init_db(path):
    database_instance = peewee.SqliteDatabase(path)

    class BaseModel(peewee.Model):
        class Meta:
            database = database_instance

    class Config(BaseModel):
        smbcrawler_version = peewee.CharField()
        created = peewee.DateTimeField(default=datetime.datetime.now)
        cmd = peewee.CharField()

    class Target(BaseModel):
        name = peewee.CharField(unique=True, index=True)
        port_open = peewee.BooleanField()
        instance_name = peewee.CharField(index=True, null=True)
        listable_authenticated = peewee.BooleanField(null=True)
        listable_unauthenticated = peewee.BooleanField(null=True)

    class Share(BaseModel):
        target = peewee.ForeignKeyField(Target, backref="shares")
        name = peewee.CharField(index=True)
        remark = peewee.CharField(default=None, null=True)

        # These are allowed to be null becaues they can be unknown at certain
        # points in time
        auth_access = peewee.BooleanField(null=True)
        guest_access = peewee.BooleanField(null=True)
        write_access = peewee.BooleanField(null=True)
        read_level = peewee.IntegerField(null=True)
        maxed_out = peewee.BooleanField(null=True)

    class FileContents(BaseModel):
        content = peewee.BlobField(unique=True, index=True)
        clean_content = peewee.TextField(null=True)

    class Path(BaseModel):
        name = peewee.CharField(index=True)
        parent = peewee.ForeignKeyField("self", null=True, backref="children")
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
        target = peewee.ForeignKeyField(Target, backref="events", null=True)

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
        share = peewee.ForeignKeyField(
            Share, backref="finding_readable_high_value_shares"
        )

    class WritableHighValueShare(Finding):
        share = peewee.ForeignKeyField(
            Share, backref="finding_writeable_high_value_shares"
        )

    class GuestAccess(Finding):
        share = peewee.ForeignKeyField(Share, backref="finding_guest_access")

    class LogItem(BaseModel):
        timestamp = peewee.DateTimeField(default=datetime.datetime.now)
        message = peewee.CharField()
        level = peewee.CharField()
        thread_id = peewee.IntegerField()
        line_no = peewee.IntegerField()
        module = peewee.CharField()
        exc_info = peewee.CharField(null=True)

    models = BaseModel.__subclasses__()

    with database_instance:
        database_instance.create_tables(models)

    models = {m.__name__: m for m in models}

    # TODO check for present row in Config. offer to resume scan.

    db_instance = DbInstance(database_instance, models)

    Config.create(
        dict(
            smbcrawler_version=__version__,
            cmd="TODO",
        )
    )

    return db_instance


@functools.cache
def memoized_get(model, *args, **kwargs):
    return model.get(**args, **kwargs)


def replace_foreign_keys(models, row):
    """Replace strings that represent a foreign relationship with the
    respective object"""

    table = row[0]
    data = row[1]

    if table == "event":
        m = models["Target"]
        target = data["name"]
        if target:
            data["name"] = memoized_get(m, m.name == target)

        m = models["Share"]
        share = data["share"]
        if target and share:
            data["share"] = memoized_get(m, m.target == target & m.name == share)

        m = models["Path"]
        path = data["path"]
        if target and share and path:
            data["path"] = memoized_get(
                m, m.target == target & m.share == share & m.name == path
            )


def process_rows(db_instance, rows):
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
            filter_ = row[2]
            # If filter_ is not none, use it to query an object and update it.
            # Else, insert new object.

            replace_foreign_keys(models, row)

            if filter_:
                query = [getattr(model, k) == v for k, v in filter_.items()]
                model.update(data).where(*query).execute()
            else:
                if isinstance(data, dict):
                    model.create(**data)
                elif isinstance(data, list):
                    # This is special case where we add the path tree. Prolly
                    # should do this better.
                    # TODO Idea: The queue should contain callables, i.e. "tasks"
                    if model.__name__ == "Path":
                        insert_paths(models, data[0], data[1], data[2])


def insert_paths(models, target, share, paths):
    if not paths:
        return
    Share = models["Share"]
    share = Share.get(Share.name == str(share), Share.target == str(target))

    def recursive_insert(parent, paths):
        for p in paths:
            path_object = models["Path"].create(
                name=p.get_shortname(), parent=parent, share=share.name, size=p.size
            )
            recursive_insert(path_object, p.paths)

    recursive_insert(None, paths)


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

    def write(self, table, data, filter_=None):
        self.queue.put((table, data, filter_))

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
        process_rows(self.db_instance, self._batch)
        self._batch = []

    def close(self, force=False):
        if not self.finished.is_set():
            self.finished.set()
            self.queue.put_nowait(self.DONE)
            self.thread.join()
