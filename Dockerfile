FROM python:3.9

RUN apt update && apt install -y apache2 apache2-dev python3-pip

WORKDIR /gateway_server

# COPY ["src", "apache.wsgi", "requirements.txt", "/gateway_server"]

COPY . .

RUN pip install --no-cache-dir wheel
RUN pip install --no-cache-dir --force-reinstall -r requirements.txt

# RUN pip config set global.cert /usr/local/share/ca-certificates/server.pem

# EXPOSE ${SSL_PORT}

# CMD ["flask", "--app", "src/main", "run"]
RUN usermod -u 1000 www-data
RUN usermod -G root www-data

CMD mod_wsgi-express start-server wsgi_script.py \
	--user www-data \
	--group www-data \
	--port '${PORT}' \
	--ssl-certificate-file '${SSL_CERTIFICATE}' \
	--ssl-certificate-key-file '${SSL_KEY}' \
	--ssl-certificate-chain-file '${SSL_PEM}' \
	--https-only --server-name '${HOST}' --https-port '${SSL_PORT}' \
	--log-to-terminal
