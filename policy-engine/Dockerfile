FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8080
CMD sh -c "chmod 600 /etc/service-certs/*.key 2>/dev/null; python main.py"
