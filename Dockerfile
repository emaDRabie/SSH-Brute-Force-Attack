FROM python:3.10-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install tshark + tcpdump
RUN apt-get update && \
    apt-get install -y tshark tcpdump && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy IDS code + model
COPY live_ssh_ids_ml.py .
COPY ssh_ids_model.pkl .

# tshark needs root → OK in container
CMD ["python", "-u", "live_ssh_ids_ml.py"]
