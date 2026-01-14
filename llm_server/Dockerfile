FROM pytorch/pytorch:2.1.2-cuda12.1-cudnn8-runtime

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    flask \
    transformers \
    accelerate \
    bitsandbytes \
    scipy

COPY app.py .

EXPOSE 8900

ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]