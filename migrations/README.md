# Database Migration Script

This script allows you to apply database migrations using a JSON specification
file. It uses the Peewee ORM and the Playhouse migrations module for database
operations.

## Getting Started

### Prerequisites

- Python 3.x installed on your system
- Peewee ORM (`pip install peewee`)

### Usage

```bash
python3 -m migrations.run <spec_version>
```

Replace `<spec_version>` with the version of the migration specification file
you want to apply.

For example:

```bash
python3 -m migrations.run v1.0.0
```

### Spec File Format

The migration specification file is a JSON file that defines the schema changes
to be applied. Here's a sample format:

```json
[
	{
		"action": "add_column",
		"table": "users",
		"column_name": "age",
		"field": "IntegerField()"
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
```

### Supported Actions

- `add_column`
- `drop_column`
- `rename_column`
- `add_not_null`
- `drop_not_null`
- `rename_table`
- `add_index`
- `drop_index`

Each action requires specific parameters as mentioned in the sample spec file
format.
