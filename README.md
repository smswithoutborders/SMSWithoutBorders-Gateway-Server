# SMSWithoutBorders Gateway Server
### Requirements
- python3
- RabbitMQ


### Features
- Message broker server for [Gateway-Client]() (_see [SMSWithoutBorders-OpenAPI]()_ )
- [SMSWithoutBorders-App]() synchronization for communication with [Publisher]()
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
```

### Configuration
- Copy the config files and edit the
```
cp .configs/example.config.ini .configs/config.ini
```
