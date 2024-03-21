FROM python:3.9

# Install necessary system dependencies
RUN apt update && apt install -y apache2 apache2-dev python3-pip libapache2-mod-wsgi-py3

# Set the working directory
WORKDIR /gateway_server

# Copy the entire project directory into the container
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir wheel
RUN pip install --no-cache-dir --force-reinstall -r requirements.txt

# Set permissions
RUN usermod -u 1000 www-data
RUN usermod -G root www-data

# Set up Apache with mod_wsgi
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

# Update Apache configuration
RUN sed -i "s/15002/$( echo $PORT )/g" apache.conf
RUN echo "Include '/gateway_server/apache.conf'" | \
	cat - /tmp/httpd/httpd.conf > /tmp/file.txt | \
	mv /tmp/file.txt /tmp/httpd/httpd.conf

# CMD to start Apache and run the imap_listener module
CMD python3 -m src.imap_listener && \
	/tmp/httpd/apachectl -k start && \
	touch /tmp/httpd/error.log && \
	tail -n 50 -f /tmp/httpd/error.log
