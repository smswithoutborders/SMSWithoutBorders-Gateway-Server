"""
Database migration tool using peewee ORM.

Applies schema changes defined in JSON spec file.
"""

import os
import json
import argparse
import logging

import peewee
from playhouse.migrate import MySQLMigrator, migrate

from src.db import connect

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("[DB MIGRATOR]")


db = connect()

migrator = MySQLMigrator(db)
MIGRATION_DIR = "migrations"

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
    """Parse a field string from spec into a Field instance."""
    field_type = field_str.split("(")[0]
    if field_type not in ALLOWED_FIELDS:
        raise ValueError(f"Unsupported field: {field_type}")
    return eval("peewee." + field_str)


def migrate_operations(operations):
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


def check_and_migrate_schema(current_schema_version):
    """Check schema version and migrate if necessary."""
    latest_schema_version = get_latest_schema_version()

    if current_schema_version != latest_schema_version:
        logger.info(
            "Migration required. Migrating to latest schema version: %s",
            latest_schema_version,
        )
        spec = load_spec(latest_schema_version)
        migrate_operations(spec)
        logger.info("Migration completed.")
    else:
        logger.info("Database schema is up to date.")


def get_latest_schema_version():
    """Get the latest schema version."""
    if not os.path.isdir(MIGRATION_DIR):
        return None

    migration_files = [
        file
        for file in os.listdir(MIGRATION_DIR)
        if file.startswith("v") and file.endswith(".json")
    ]
    versions = sorted(migration_files, reverse=True)

    return versions[0].rstrip(".json") if versions else None


def load_spec(spec_version):
    """Load and return the JSON spec."""
    spec_file_path = os.path.join(MIGRATION_DIR, f"{spec_version}.json")

    if not os.path.exists(spec_file_path):
        raise FileNotFoundError(f"Spec file '{spec_file_path}' not found.")

    with open(spec_file_path, encoding="utf-8") as f:
        return json.load(f)


def main():
    """Main function to parse arguments and initiate migration."""
    parser = argparse.ArgumentParser(
        usage="python3 -m migrations [-h] spec_version",
        description="Apply database migrations",
    )
    parser.add_argument("spec_version", help="spec version to apply")
    args = parser.parse_args()
    spec = load_spec(args.spec_version)
    migrate_operations(spec)


if __name__ == "__main__":
    main()
