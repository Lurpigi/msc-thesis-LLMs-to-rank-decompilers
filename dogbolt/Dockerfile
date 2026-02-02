FROM alpine:latest

RUN apk add --no-cache bash curl jq tree coreutils
    
WORKDIR /app

RUN mkdir -p bin

WORKDIR /app
# COPY bin/ ./bin/
COPY dogbolt.sh .
COPY run.sh .
COPY decompress.sh .

RUN dos2unix dogbolt.sh run.sh decompress.sh && \
    chmod +x dogbolt.sh run.sh decompress.sh

CMD ["bash", "./run.sh"]