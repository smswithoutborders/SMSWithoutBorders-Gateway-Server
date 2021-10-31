### Installation
```bash
https://github.com/smswithoutborders/SMSWithoutBorders-Gateway-Server.git
git submodule update --force --recursive --init --remote
cd SMSWithoutBorders-Gateway-Server 
python3 -m virtualenv venv
. venv/bin/activate
pip3 install -r requirements.txt
```


### Usage
```bash
. venv/bin/activate
python3 app.py
```

#### API endpoints
##### New SMS request
<b>+ POST<br>
/sms/<country></b>
```json
{
	"auth_id":<string>,
	"auth_key":<string>,
	"data":[{
		"isp":<string> //lowcase
		"number":<string> //E.164 standard required]
		"text":<sring>},
	...]
}
```
