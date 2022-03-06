# SMSWithoutBorders Gateway Server
### Requirements
- python3
- RabbitMQ


### Features
- Message broker server for [Gateway-Client]() (_see [SMSWithoutBorders-OpenAPI]()_ )
- [SMSWithoutBorders-App]() [synchronization](synchronization) for communication with [Publisher]()
	> This should should be hosted in the same place as [Publisher](), because Publisher is not _directly_ exposed to the web.
- Forwards publishing request from [Gateway-Client]() to [Publisher]()
- Authenticates [Gateway-Client's]() request to join [Publisher]()

### Installation
```bash
https://github.com/smswithoutborders/SMSWithoutBorders-Gateway-Server.git
git submodule update --force --recursive --init --remote
cd SMSWithoutBorders-Gateway-Server 
python3 -m virtualenv venv
. venv/bin/activate
pip3 install -r requirements.txt
make
```

### Directory structure
_/gateway_server_ \
Contains the Gateway [server websocket](gateway_server/sessions_websocket.py) sessions which is required to synchronize users.


### Configuration
#### Configuring gateway's API
- Copy the config files and edit the
```bash
cp confs/example.conf.ini confs/conf.ini
```

#### Configuring gateway server
- Copy the config files and edit the
```bash
cp gateway_server/confs/example.conf.ini gateway_server/confs/conf.ini
```

#### How to-s
<a name="synchronization" />

#### Start Gateway API

##### Manually start Gateway API
```bash
. venv/bin/activate
python3 api.py
```

#### Synchronization
Synchronization is required to enable the users acquire security keys, platforms and available gateways.

##### Manually setup sessions websocket
```bash
. venv/bin/activate
python3 gateway_server/sessions_websocket.py
```

##### Configurations
All configurations for websockets can be done in the `conf.ini` file in `gateway_server` \
`session_change_limit` : Number of times client websocket will receive session change urls \
`session_sleep_timeout` : Number of seconds to sleep after sending a session change url to the client \
`session_paused_timeout` : Number of seconds to remain in paused state before closing connection

##### Synchronization flow
1. Begin by requesting for a new session. \
`GET /<api-version>/sync/users/<user-id>` \
\
This returns a string url, which can be connected to by websocket clients. The users can begin communicating with this \
returned URL or scan them through the QR scan function in the app. The frequency of change of the synchronization urls depends
on the configuration settings `[sync] session_sleep_timeout` (defaults = 15 seconds). \
\
The total number of changes per frequency can be changed in `[sync] session_change_limit` (defaults = 3 times) \

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

```bash
./websocat_linux64 ws://localhost:6996/v2/sync/init/111/000
```

- Testing [RSA Encryption/Decryption](test/security_rsa.py)
This will require pem files. Copy them into the test/ dir to allow test run
```bash
python -m unittest test/security_rsa.py
```
