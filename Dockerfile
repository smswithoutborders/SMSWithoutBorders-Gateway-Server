FROM python:3.10

RUN apt update && apt install -y apache2 apache2-dev python3-pip less vim

WORKDIR /gateway_server

# COPY ["src", "apache.wsgi", "requirements.txt", "/gateway_server"]

COPY . .

RUN pip install -r requirements.txt
RUN pip install --force-reinstall "git+https://github.com/smswithoutborders/SMSWithoutBorders-BE-Publisher.git@main#egg=SwobBackendPublisher"

# RUN pip config set global.cert /usr/local/share/ca-certificates/server.pem

# EXPOSE ${SSL_PORT}

# CMD ["flask", "--app", "src/main", "run"]
CMD mod_wsgi-express start-server wsgi_script.py \
	--user www-data \
	--group www-data \
	--port '${PORT}' \
	--ssl-certificate-file '${SSL_CERTIFICATE}' \
	--ssl-certificate-key-file '${SSL_KEY}' \
	--ssl-certificate-chain-file '${SSL_PEM}' \
	--https-only --server-name '${HOST}' --https-port '${SSL_PORT}'
