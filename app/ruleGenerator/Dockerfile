FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/

# -------- install supercronic -------------
ADD https://github.com/aptible/supercronic/releases/download/v0.2.29/supercronic-linux-amd64 /usr/local/bin/supercronic
RUN chmod +x /usr/local/bin/supercronic
# -------- crontab -------------------------
COPY crontab /etc/crontab

RUN mkdir -p /app/out

ENTRYPOINT ["/usr/local/bin/supercronic", "/etc/crontab"]
