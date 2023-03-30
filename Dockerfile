FROM python:3.9

RUN apt update && apt install -y apache2 apache2-dev python3-pip libapache2-mod-wsgi-py3

WORKDIR /gateway_server

# COPY ["src", "apache.wsgi", "requirements.txt", "/gateway_server"]

COPY . .

RUN pip install --no-cache-dir wheel
RUN pip install --no-cache-dir --force-reinstall -r requirements.txt

# RUN pip config set global.cert /usr/local/share/ca-certificates/server.pem

# CMD ["flask", "--app", "src/main", "run"]
RUN usermod -u 1000 www-data
RUN usermod -G root www-data

ARG PORT=$PORT
ARG HOST
ARG SSL_CERTIFICATE
ARG SSL_KEY
ARG SSL_PEM
ARG SSL_PORT

RUN mod_wsgi-express setup-server wsgi_script.py \
	--setup-only \
	--server-root /tmp/httpd \
	--error-log-name /tmp/httpd/error.log \
	--access-log-name /tmp/httpd/error.log \
	--startup-log-name /tmp/httpd/error.log \
	--log-level='debug' \
	--user www-data \
	--group www-data \
	--port $PORT \
	--server-name ${HOST} \
	--ssl-certificate-file ${SSL_CERTIFICATE} \
	--ssl-certificate-key-file ${SSL_KEY} \
	--ssl-certificate-chain-file ${SSL_PEM} \
	--https-port ${SSL_PORT}

RUN sed -i "s/15002/$( echo $PORT )/g" apache.conf
RUN echo "Include '/gateway_server/apache.conf'" | \
	cat - /tmp/httpd/httpd.conf > /tmp/file.txt | \
	mv /tmp/file.txt /tmp/httpd/httpd.conf

CMD /tmp/httpd/apachectl -k start && \
	touch /tmp/httpd/error.log && \
	tail -n 50 -f /tmp/httpd/error.log
