FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ /app/src/ruleGenerator/core/
COPY src/  /app/src/ruleGenerator/src/

# ---- supercronic ----
ADD https://github.com/aptible/supercronic/releases/download/v0.2.33/supercronic-linux-amd64 /usr/local/bin/supercronic
RUN chmod +x /usr/local/bin/supercronic

# ---- entrypoint ----
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /app/out

ENTRYPOINT ["/app/entrypoint.sh"]
