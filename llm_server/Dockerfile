FROM nvidia/cuda:12.1.1-runtime-ubuntu22.04

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates python3 python3-pip\
    && rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/bin/python3 /usr/bin/python

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/app.py

EXPOSE 8900

ENV PYTHONUNBUFFERED=1
ENV CUDA_LAUNCH_BLOCKING=1 
ENV TORCH_USE_CUDA_DSA=1

CMD ["python", "app.py"]