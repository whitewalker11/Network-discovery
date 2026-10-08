FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY agent ./agent
COPY static ./static
COPY data ./data
EXPOSE 8010
CMD ["uvicorn","app.main:app","--host","127.0.0.1","--port","8010"]
