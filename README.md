# SMSWithoutBorders Gateway Server

## API References

- [API Version 3](/docs/api_v3.md)

## Requirements

- [MySQL](https://www.mysql.com/) (version >= 8.0.28)
  ([MariaDB](https://mariadb.org/))
- [Python](https://www.python.org/) (version >=
  [3.8.10](https://www.python.org/downloads/release/python-3810/))
- [Python Virtual Environments](https://docs.python.org/3/tutorial/venv.html)

## Dependencies

On Ubuntu, install the following dependencies:

```bash
sudo apt install python3-dev libmysqlclient-dev apache2 apache2-dev make libapache2-mod-wsgi-py3
```

> [!NOTE] 
> This gateway server has strong dependencies on the [Backend](https://github.com/smswithoutborders/SMSwithoutborders-BE) 
> User Databases.

## Linux Environment Variables

Variables used for the Project:

- MYSQL_HOST
- MYSQL_USER
- MYSQL_PASSWORD
- MYSQL_DATABASE
- SHARED_KEY
- HASHING_SALT
- ORIGINS
- HOST
- PORT
- RMQ_HOST
- RABBITMQ_DEFAULT_USER
- RABBITMQ_DEFAULT_PASS
- IMAP_SERVER
- IMAP_PORT
- IMAP_USERNAME
- IMAP_PASSWORD
- MAIL_FOLDER
- FTP_USERNAME
- FTP_PASSWORD
- FTP_IP_ADDRESS
- FTP_PORT
- FTP_PASSIVE_PORTS
- FTP_READ_LIMIT
- FTP_WRITE_LIMIT
- FTP_MAX_CON
- FTP_MAX_CON_PER_IP
- FTP_DIRECTORY
- DEKU_CLOUD_URL
- DEKU_CLOUD_PROJECT_REF
- DEKU_CLOUD_SERVICE_ID
- DEKU_CLOUD_ACCOUNT_SID
- DEKU_CLOUD_AUTH_TOKEN
- SSL_CERTIFICATE
- SSL_KEY

## Installation

### Clone the Repository

Clone the SMSWithoutBorders Gateway Server repository from GitHub:

```bash
git clone https://github.com/smswithoutborders/SMSWithoutBorders-Gateway-Server.git
cd SMSWithoutBorders-Gateway-Server
```

Install all Python packages:

### Pip

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Build and Run with Docker

1. **Build Docker Image:**

   Ensure you have Docker installed on your system. Then, navigate to the root
   directory of the cloned repository and run the following command to build the
   Docker image:

   ```bash
   docker build -t smswithoutborders-gateway-server .
   ```

   Replace `smswithoutborders-gateway-server` with your desired image name.

2. **Run Docker Container:**

   After the image is built, run a Docker container using the following command:

   ```bash
   docker run -d -p 5000:5000 --name gateway-server smswithoutborders-gateway-server
   ```

   Adjust the port mapping (`-p`) and container name (`--name`) as needed.

3. **Verify Container:**

   Verify that the container is running by checking its status:

   ```bash
   docker ps
   ```

   This should display the running containers, including the SMSWithoutBorders
   Gateway Server container.

## Running

For quicker development, you can integrate the
[BE Dependencies](https://github.com/smswithoutborders/SMSwithoutborders-BE)
databases.

> In cases where the BE Database and Gateway server share the same database:

```bash
MYSQL_HOST=host \
MYSQL_PORT=port \
MYSQL_USERNAME=username \
MYSQL_DATABASE=dbname \
flask --debug --app src.main run
```

> In cases where the BE Database and Gateway server don't share the same
> database:

```bash
MYSQL_HOST=host \
MYSQL_PORT=port \
MYSQL_USERNAME=username \
MYSQL_DATABASE=dbname \
MYSQL_BE_HOST=host \
MYSQL_BE_PORT=port \
MYSQL_BE_USERNAME=username \
MYSQL_BE_DATABASE=dbname \
flask --debug --app src.main run
```

## Use cases

**Synchronization**

Synchronization prepares the app for secured conversation using shared keys.

**Synchronization flow**

1. Begin by requesting a new session: `GET /<api-version>/sync/users/<user-id>`

   This returns a URL string, which can be connected to by websocket clients.
   Users can begin communicating with this returned URL or scan them through the
   QR scan function in the app. The frequency of change of the synchronization
   URLs depends on the configuration settings (defaults = 15 seconds).

   The total number of changes per frequency can be changed (defaults = 3
   times).

   Response:

   - `200`: session created
   - `500`: some error occurred, check debug logs

2. Once a sync URL is connected and begins processing, the websocket sends a
   pause text `201- pause`. The user begins authenticating themselves and adding
   their security policies to their record on the server.

3. Once the user has performed the necessary handshake and the information
   exchange has begun, the websocket sends an acknowledgment text `200- ack`.

## Testing

- Testing [Users model](gateway_server/users.py):

```bash
python -m unittest gateway_server/test/UTestUsers.py
```

- Testing [WebSockets](gateway_server/sessions_websocket.py):

Install [websocat](https://github.com/vi/websocat) and
[jq](https://stedolan.github.io/jq/):

_Manjaro:_

```bash
sudo pacman -S websocat jq
```

Test websocket:

```bash
websocat ws://localhost:6996/v2/sync/init/111/000
```

- Testing [RSA Encryption/Decryption](test/security_rsa.py): This will require
  pem files. Copy them into the test/ directory to allow the test run.

```bash
python -m unittest test/security_rsa.py
```

- Testing [Entire Handshake process](test/handshake.py): This will require pem
  files. Copy them into the test/ directory to allow the test run.

```bash
./test/handshake.sh
```

## Scripts

### FTP Server

```bash
MYSQL_HOST= \
MYSQL_USER= \
MYSQL_PASSWORD= \
MYSQL_DATABASE= \
FTP_USERNAME= \
FTP_PASSWORD= \
FTP_IP_ADDRESS= \
FTP_PORT= \
FTP_PASSIVE_PORTS= \
FTP_READ_LIMIT= \
FTP_WRITE_LIMIT= \
FTP_MAX_CON= \
FTP_MAX_CON_PER_IP= \
FTP_DIRECTORY= \
SSL_CERTIFICATE= \
SSL_KEY= \
python3 -m src.ftp_server
```

### IMAP Listener

```bash
MYSQL_HOST= \
MYSQL_USER= \
MYSQL_PASSWORD= \
MYSQL_DATABASE= \
IMAP_SERVER= \
IMAP_PORT= \
IMAP_USERNAME= \
IMAP_PASSWORD= \
MAIL_FOLDER= \
SSL_CERTIFICATE= \
SSL_KEY= \
python3 -m src.imap_listener
```

### Reliability Test CLI

```bash
MYSQL_HOST= \
MYSQL_USER= \
MYSQL_PASSWORD= \
MYSQL_DATABASE= \
SHARED_KEY= \
DEKU_CLOUD_URL= \
DEKU_CLOUD_PROJECT_REF= \
DEKU_CLOUD_SERVICE_ID= \
DEKU_CLOUD_ACCOUNT_SID= \
DEKU_CLOUD_AUTH_TOKEN= \
python3 -m rt_cli
```

> [!TIP]
> Use `-h` to see the command and arguments the CLI uses.

### GateWay Clients CLI

```bash
MYSQL_HOST= \
MYSQL_USER= \
MYSQL_PASSWORD= \
MYSQL_DATABASE= \
python3 -m gc_cli
```

> [!TIP]
> Use `-h` to see the command and arguments the CLI uses.

### Reliability Test Checker

```bash
MYSQL_HOST= \
MYSQL_USER= \
MYSQL_PASSWORD= \
MYSQL_DATABASE= \
python3 -m src.reliability_test_checker
```
