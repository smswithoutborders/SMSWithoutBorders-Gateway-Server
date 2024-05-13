"""
Database migration tool using peewee ORM.

Applies schema changes defined in JSON spec file.
"""

import json
import argparse

import peewee
from playhouse.migrate import MySQLMigrator, migrate

from src.db import connect

db = connect()

migrator = MySQLMigrator(db)

ACTIONS = {
    "add_column": migrator.add_column,
    "drop_column": migrator.drop_column,
    "rename_column": migrator.rename_column,
    "add_not_null": migrator.add_not_null,
    "drop_not_null": migrator.drop_not_null,
    "rename_table": migrator.rename_table,
    "add_index": migrator.add_index,
    "drop_index": migrator.drop_index,
}

ALLOWED_FIELDS = ["CharField", "DecimalField"]

PENDING = "⏳"
SUCCESS = "✅"
FAILED = "❌"


def parse_field(field_str):
    """
    Parse a field string from spec into a Field instance.

    Args:
        field_str (str): Field string like 'IntegerField()'

    Returns:
        Field: Instantiated Field such as IntegerField

    Raises:
        ValueError: If field_str is not a supported field
    """
    if field_str.split("(")[0] not in ALLOWED_FIELDS:
        raise ValueError(f"Unsupported field: {field_str}")

    return eval("peewee." + field_str)


def run_migrate(operations):
    """
    Execute migration operations.

    Args:
        operations (list): Migration actions to run

    Raises:
        MigrationError: On any migration failure
    """
    migrations_done = 0
    migrations_failed = 0

    for operation in operations:
        print("============================================\n")
        print(f"Performing operation: {operation}", end="")
        print(f" {PENDING}", end="\b")

        try:
            action = operation.pop("action")

            if operation.get("field"):
                operation["field"] = parse_field(operation["field"])

            if action not in ACTIONS:
                raise ValueError(f"Unsupported action: {action}")

            migrate(ACTIONS[action](**operation))

            migrations_done += 1
            print(f"{SUCCESS}")
            print("\n============================================\n")
        except Exception as error:
            print(f"{FAILED}")
            print(f"Error: {error}")
            print("\n============================================\n")
            migrations_failed += 1

    print(f"{SUCCESS} Completed migrations : {migrations_done}")
    print(f"{FAILED} Failed migrations : {migrations_failed}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        usage="migrate_db.py [-h] spec_file",
        description="Apply database migrations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("spec_file", help="path to JSON spec file")

    parser.epilog = """Supported actions:\n
add_column: "table", "column_name", "field"
drop_column: "table", "column_name", "cascade"
rename_column: "table", "old_name", "new_name" 
add_not_null: "table", "column"
drop_not_null: "table", "column"
rename_table: "old_name", "new_name"
add_index: "table", "columns", "unique"
drop_index: "table", "index_name"

Sample spec file format:\n
[
    {
        "action": "add_column",
        "table": "users",
        "column_name": "age",  
        "field": IntegerField()
    },
    {
        "action": "drop_column",
        "table": "posts",
        "column_name": "author_id",
        "cascade": true
    },
    {
        "action": "rename_column",
        "table": "posts",
        "old_name": "title",
        "new_name": "post_title"
    },
    {
        "action": "add_not_null",
        "table": "comments",
        "column": "post_id"
    },
    {
        "action": "rename_table",
        "old_name": "posts",
        "new_name": "articles"
    },
    {
        "action": "add_index",
        "table": "articles",
        "columns": ["status", "created_at"],
        "unique": true
    },
    {  
        "action": "drop_index",
        "table": "comments",
        "index_name": "post_id" 
    }
]
"""

    args = parser.parse_args()

    with open(args.spec_file, encoding="utf-8") as f:
        spec = json.load(f)
        run_migrate(spec)
