# Sentinel inference API — offline, no outbound calls at runtime.
FROM python:3.13-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# system deps kept minimal; scapy (optional PCAP) needs libpcap at runtime
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pipeline ./pipeline
COPY models ./models
COPY backend ./backend
COPY config ./config
COPY data ./data
COPY train.py .

EXPOSE 8000
# train the model if weights are absent (they ship in the repo), then serve
CMD ["sh", "-c", "test -f models/world_model.npz || python train.py; uvicorn backend.main:app --host 0.0.0.0 --port 8000"]
