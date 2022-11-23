FROM python:3.10

RUN apt update && apt install -y apache2 apache2-dev python3-pip

WORKDIR /gateway_server

# COPY ["src", "apache.wsgi", "requirements.txt", "/gateway_server"]

COPY . .

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["flask", "--app", "src/main", "run"]
