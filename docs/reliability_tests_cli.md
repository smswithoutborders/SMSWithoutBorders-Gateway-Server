# Reliability Tests CLI

This CLI (Command Line Interface) tool provides functionalities to trigger and
view reliability tests for gateway clients.

## Prerequisites

- [Python](https://www.python.org/) (version >=
  [3.8.10](https://www.python.org/downloads/release/python-3810/))

Ensure the following environment variables are set:

- `DEKU_CLOUD_URL`: URL for Deku Cloud service.
- `DEKU_CLOUD_PROJECT_REF`: Project reference for Deku Cloud.
- `DEKU_CLOUD_SERVICE_ID`: Service ID for Deku Cloud.
- `DEKU_CLOUD_ACCOUNT_SID`: Account SID for Deku Cloud.
- `DEKU_CLOUD_AUTH_TOKEN`: Authentication token for Deku Cloud.
- `SHARED_KEY_FILE`: Path to the file containing the shared encryption key.
- `MYSQL_HOST`: The hostname or IP address of the MySQL server.
- `MYSQL_USER`: The MySQL user with appropriate privileges to access the
  database.
- `MYSQL_PASSWORD`: The password for the MySQL user.
- `MYSQL_DATABASE`: The name of the MySQL database where the reliability tests
  records will be stored.

> [!NOTE] 
> The Reliability Tests CLI depends on the availability of gateway
> clients. Make sure to have gateway clients set up before triggering
> reliability tests. For information on setting up gateway clients, refer to the
> [Gateway Clients CLI documentation](gateway_clients_cli.md).

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

### Starting Tests

To start reliability tests for a specific MSISDN or for all MSISDNs, use the
following command:

```bash
python rt_cli.py start [--msisdn MSISDN] [--all]
```

- `--msisdn MSISDN`: Specify the MSISDN for which tests are to be started.
- `--all`: Start tests for all MSISDNs.

### Viewing Test Data

To view test data for a specific MSISDN or for all test data in the database,
use the following command:

```bash
python rt_cli.py view [--msisdn MSISDN]
```

- `--msisdn MSISDN`: Specify the MSISDN for which test data is to be viewed.

## Examples

### Starting Tests

Start tests for a specific MSISDN:

```bash
python rt_cli.py start --msisdn +1234567890
```

Start tests for all MSISDNs:

```bash
python rt_cli.py start --all
```

### Viewing Test Data

View test data for a specific MSISDN:

```bash
python rt_cli.py view --msisdn +1234567890
```

View all test data:

```bash
python rt_cli.py view
```

## Setting up Linux Cron Jobs

To automate the execution of reliability tests at regular intervals using cron
jobs, follow these steps:

1. Open the crontab file using the command:

```bash
crontab -e
```

2. Add a new cron job entry to execute the reliability tests script. For
   example, to run the tests every day at 2:00 AM, add the following line:

```bash
0 2 * * * /usr/bin/python /path/to/rt_cli.py start --all >> /path/to/logfile.log 2>&1
```

> [!INFO] Replace `/usr/bin/python` with the path to your Python interpreter,
> `/path/to/rt_cli.py` with the actual path to your script, and
> `/path/to/logfile.log` with the path where you want to store the log output.

3. Save and exit the crontab file. The cron job will now be scheduled to run at
   the specified time.

> [!NOTE]
>
> - Ensure that the Python interpreter path and script path are correctly
>   specified in the cron job entry.
> - Verify the cron job execution and check the log file for any errors or
>   issues.
> - Adjust the cron job schedule as needed based on your testing requirements.
