FROM python:3.10

RUN apt update && apt install -y python3-pip

WORKDIR /sync_sockets

COPY . .

RUN pip install -r requirements.txt

CMD ["python3", "sync_sockets.py"]

EXPOSE 15001
