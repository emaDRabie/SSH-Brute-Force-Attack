FROM python:3.10-slim

# Install tshark + dependencies
RUN apt-get update && \
    apt-get install -y tshark tcpdump && \
    rm -rf /var/lib/apt/lists/*

# Prevent interactive prompt
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy IDS code + model
COPY live_ssh_ids_ml.py .
COPY ssh_ids_model.pkl .

# tshark needs root
CMD ["python", "live_ssh_ids_ml.py"]
