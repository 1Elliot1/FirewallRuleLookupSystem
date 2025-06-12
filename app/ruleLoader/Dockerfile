# rule_loader/Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .       
RUN pip install --no-cache-dir -r requirements.txt
COPY uploadToES.py .
COPY test_template.json /app/test_template.json
