# Gateway Clients CLI

The Gateway Clients CLI provides functionalities to manage gateway clients. It
interacts with a database to perform CRU (Create, Read, Update) operations on
client data.

## Prerequisites

- [Python](https://www.python.org/) (version >=
  [3.8.10](https://www.python.org/downloads/release/python-3810/))

Ensure the following environment variables are set:

- `MYSQL_HOST`: The hostname or IP address of the MySQL server.
- `MYSQL_USER`: The MySQL user with appropriate privileges to access the
  database.
- `MYSQL_PASSWORD`: The password for the MySQL user.
- `MYSQL_DATABASE`: The name of the MySQL database where the gateway client
  records will be stored.

## Installation

1. **Set up Virtual Environment**:

   Create and activate a virtual environment to manage project dependencies:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On macOS and Linux
   venv\Scripts\activate     # On Windows
   ```

2. **Install Dependencies**:

   Install required Python dependencies using `pip`:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Create

To create a new gateway client, use the following command:

```bash
python gc_cli.py create --msisdn MSISDN --protocols PROTOCOLS
```

- `--msisdn MSISDN`: Specify the MSISDN (Mobile Station International Subscriber
  Directory Number) of the client.
- `--protocols PROTOCOLS`: Specify the protocol(s) of the client, separated by
  commas.

### View

To view details of existing gateway client(s), use the following command:

```bash
python gc_cli.py view [--msisdn MSISDN]
```

- `--msisdn MSISDN`: (Optional) Specify the MSISDN of the client to view. If not
  provided, details of all clients will be displayed.

### Update

To update details of an existing gateway client, use the following command:

```bash
python gc_cli.py update --msisdn MSISDN [--country COUNTRY] [--operator OPERATOR] [--protocols PROTOCOLS]
```

- `--msisdn MSISDN`: Specify the MSISDN of the client to update.
- `--country COUNTRY`: (Optional) Specify the new country value for the client.
- `--operator OPERATOR`: (Optional) Specify the new operator value for the
  client.
- `--protocols PROTOCOLS`: (Optional) Specify the new protocol(s) value for the
  client, separated by commas.
