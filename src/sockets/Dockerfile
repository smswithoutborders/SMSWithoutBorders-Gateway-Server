FROM python:3.10

RUN apt update && apt install -y python3-pip

WORKDIR /sync_sockets

COPY ./src/sockets/sync_sockets.py .
COPY ./requirements.txt requirements.txt

RUN pip install -r requirements.txt

EXPOSE 15001

CMD ["python3", "sync_sockets.py"]

