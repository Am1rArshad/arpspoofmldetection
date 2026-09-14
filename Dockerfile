FROM node:22-alpine AS frontend-builder

WORKDIR /frontend
COPY frontend/package.json .
RUN npm install
COPY frontend/ .
RUN npm run build

FROM python:3.10-slim

# Install system dependencies for Scapy and networking
RUN apt-get update && \
    apt-get install -y tcpdump iproute2 iputils-ping net-tools && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .
COPY --from=frontend-builder /frontend/dist ./frontend/dist

EXPOSE 8000

# Allow Streamlit to run as root (for Docker)
ENV STREAMLIT_SERVER_HEADLESS=true
ENV API_PORT=8000
ENV STREAMLIT_SERVER_ENABLECORS=false

COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

CMD ["./entrypoint.sh"] 