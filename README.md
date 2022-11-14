# SMSWithoutBorders Gateway Server

This is a middle-ware and has strong dependencies on the Backend User Databases.

To auto populate a Backend User Database in development stage use \
`make dev` to automatically populate the database with default values.

### Requirements
- python3
- MySQL

### Installation
```bash
https://github.com/smswithoutborders/SMSWithoutBorders-Gateway-Server.git
make
make install
```
> for docker
```bash
docker -t swob_gateway_server build .
```

### Running
For quicker development you can integrate the [BE Dependencies](https://github.com/smswithoutborders/SMSwithoutborders-BE) databases.

> In cases where BE Database and Gateway server share the same database
```bash
MYSQL_HOST=host \
MYSQL_PORT=port \
MSYQL_USERNAME=username \
MYSQL_DATABASE=dbname \
python3 -m src.main
```

> In cases where BE Database and Gateway server don't share the same database
```bash
MYSQL_HOST=host \
MYSQL_PORT=port \
MSYQL_USERNAME=username \
MYSQL_DATABASE=dbname \
MYSQL_BE_HOST=host \
MYSQL_BE_PORT=port \
MYSQL_BE_USERNAME=username \
MYSQL_BE_DATABASE=dbname \
python3 -m src.main1
```

```bash
```

### Use cases
#### Synchronization
Synchronization prepares the app for secured conversation using shared keys.

##### Synchronization flow
1. Begin by requesting for a new session. \
`GET /<api-version>/sync/users/<user-id>` \
\
This returns a string url, which can be connected to by websocket clients. The users can begin communicating with this \
returned URL or scan them through the QR scan function in the app. The frequency of change of the synchronization urls depends
on the configuration settings (defaults = 15 seconds). \
\
The total number of changes per frequency can be changed (defaults = 3 times) \

`''`, `200` session created

`''`, `500` some error occured, check debug logs

2. Once a sync url is connected and begins processing, the websocket sends a pause text `201- pause`. \
The user begins authentictating themselves and adding their security policies to their record on the server.

3. Once the user has performed the necessary handshake and the information exchange has begun, the websocket sends an \
acknowledgment text `200- ack`.

<a name="testing" />

#### Testing
- Testing [Users model](gateway_server/users.py)
```bash
python -m unittest gateway_server/test/UTestUsers.py
```

- Testing [WebSockets](gateway_server/sessions_websocket.py)

[https://github.com/vi/websocat](https://github.com/vi/websocat)

*Manjaro*
```bash
sudo pacman -S websocat jq
```

*Testing websocket*
```bash
websocat ws://localhost:6996/v2/sync/init/111/000
```

- Testing [RSA Encryption/Decryption](test/security_rsa.py)
This will require pem files. Copy them into the test/ dir to allow test run
```bash
python -m unittest test/security_rsa.py
```

- Testing [Entire Handshake process](test/handshake.py)
This will require pem files. Copy them into the test/ dir to allow test run
```bash
./test/handshake.sh
```
