import sqlite3
import uuid as uuid_lib
from typing import Callable


def init() -> Callable[[], None]:
    with open('db_schema.sql', 'r') as schema_file:
        schema = schema_file.read()

    with _connection() as connection:
        connection.executescript(schema)


def new_user() -> str:
    uuid = str(uuid_lib.uuid1()).upper()

    with _connection() as connection:
        cursor = connection.cursor()
        cursor.execute('insert into users values (null, ?)', (uuid,))

    return uuid


def exists(uuid: str) -> bool:
    with _connection() as connection:
        cursor = connection.cursor()
        cursor.execute('select count(*) from users where uuid = (?)', (uuid.upper(),))
        return cursor.fetchone()[0] != 0


def _connection():
    from config import db_path
    return sqlite3.connect(db_path)
