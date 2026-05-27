FROM python:3.11

WORKDIR /app

COPY . .

RUN pip install -i https://mirrors.aliyun.com/pypi/simple/ \
    --trusted-host mirrors.aliyun.com \
    -r requirements.txt

COPY GeoLite2-Country.mmdb /app/GeoLite2-Country.mmdb

CMD ["sh", "-c", "python honeypot.py & python app.py"]