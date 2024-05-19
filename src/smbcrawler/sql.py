import functools
import datetime
import dataclasses
import queue
import threading
import typing
import sys

import peewee

from smbcrawler.version import __version__


@dataclasses.dataclass
class DbInstance:
    database: peewee.SqliteDatabase
    models: typing.Dict[str, peewee.Model]
    path: str


@dataclasses.dataclass
class DbAction:
    pass


@dataclasses.dataclass
class DbInsert(DbAction):
    model: str
    data: dict


@dataclasses.dataclass
class DbUpdate(DbAction):
    model: str
    data: dict
    filter_: dict


@dataclasses.dataclass
class DbLinkPaths(DbAction):
    target: str
    share: str
    paths: list


def get_subclasses(cls):
    result = cls.__subclasses__()
    for each in result:
        result.extend(get_subclasses(each))

    return result


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
        high_value = peewee.BooleanField(default=False)

        # These are allowed to be null becaues they can be unknown at certain
        # points in time
        auth_access = peewee.BooleanField(null=True)
        guest_access = peewee.BooleanField(null=True)
        write_access = peewee.BooleanField(null=True)
        read_level = peewee.IntegerField(null=True)
        maxed_out = peewee.BooleanField(null=True)

    class FileContents(BaseModel):
        content = peewee.BlobField(unique=True)
        content_hash = peewee.BlobField(unique=True, index=True)
        clean_content = peewee.TextField(null=True)

    class Path(BaseModel):
        name = peewee.CharField(index=True)
        parent = peewee.ForeignKeyField("self", null=True, backref="children")
        target = peewee.ForeignKeyField(Target, backref="paths")
        share = peewee.ForeignKeyField(Share, backref="paths")
        size = peewee.IntegerField()
        content = peewee.ForeignKeyField(FileContents, backref="paths", null=True)
        high_value = peewee.BooleanField(default=False)

    class Secret(BaseModel):
        content = peewee.ForeignKeyField(FileContents, backref="finding_secrets")
        line = peewee.CharField()
        secret = peewee.CharField()

    class LogItem(BaseModel):
        timestamp = peewee.DateTimeField(default=datetime.datetime.now)
        message = peewee.CharField()
        level = peewee.CharField()
        thread_id = peewee.IntegerField()
        line_no = peewee.IntegerField()
        module = peewee.CharField()
        exc_info = peewee.CharField(null=True)
        target = peewee.ForeignKeyField(Target, backref="logitems", null=True)
        share = peewee.ForeignKeyField(Share, backref="logitems", null=True)
        path = peewee.ForeignKeyField(Path, backref="logitems", null=True)

    models = get_subclasses(BaseModel)

    with database_instance:
        database_instance.create_tables(models)

    models = {m.__name__: m for m in models}

    db_instance = DbInstance(database_instance, models, path)

    is_empty = Config.select().count() == 0
    if not is_empty:
        print("DB is not empty; choose another filename. Aborting.")
        sys.exit(1)
        # TODO offer to resume scan.

    Config.create(
        smbcrawler_version=__version__,
        cmd="TODO",
    )

    return db_instance


@functools.cache
def memoized_get(model, *args, **kwargs):
    return model.get(**args, **kwargs)


def replace_foreign_keys(models, db_action: DbAction):
    """Replace strings that represent a foreign relationship with the
    respective object"""

    m = models[db_action.model]
    data = db_action.data

    if db_action.model in ["event", "logitem"]:
        target = data["name"]
        if target:
            data["name"] = memoized_get(m, m.name == target)

        m = models["Share"]
        share = data["share"]
        if target and share:
            data["share"] = memoized_get(m, m.target == target & m.name == share)


def process_db_actions(db_instance, db_actions):
    database = db_instance.database
    models = db_instance.models

    # Ensure parent objects exist when inserting objects with foreign
    # relationships
    order = list(db_instance.models.keys())
    db_actions_sorted = sorted(
        db_actions, key=lambda item: order.index(getattr(item, "model", "LogItem"))
    )

    with database.atomic():
        for db_action in db_actions_sorted:
            # If filter_ is not none, use it to query an object and update it.
            # Else, insert new object.

            if isinstance(db_action, DbInsert):
                replace_foreign_keys(models, db_action)
                models[db_action.model].create(**db_action.data)
            elif isinstance(db_action, DbUpdate):
                replace_foreign_keys(models, db_action)
                query = [
                    getattr(models[db_action.model], k) == v
                    for k, v in db_action.filter_.items()
                ]
                updated_rows = (
                    models[db_action.model]
                    .update(db_action.data)
                    .where(*query)
                    .execute()
                )
                assert updated_rows
            elif isinstance(db_action, DbLinkPaths):
                insert_paths(models, db_action.target, db_action.share, db_action.paths)


def insert_paths(models, target, share, paths):
    if not paths:
        return
    Share = models["Share"]
    share = Share.get(Share.name == str(share), Share.target == str(target))

    def recursive_insert(parent, paths):
        for p in paths:
            path_object = models["Path"].create(
                name=p.get_shortname(),
                parent=parent,
                share=share.name,
                target=str(target),
                size=p.size,
                high_value=p.high_value,
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

    def write(self, db_action: DbAction):
        self.queue.put(db_action)

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
        process_db_actions(self.db_instance, self._batch)
        self._batch = []

    def close(self, force=False):
        if not self.finished.is_set():
            self.finished.set()
            self.queue.put_nowait(self.DONE)
            self.thread.join()
