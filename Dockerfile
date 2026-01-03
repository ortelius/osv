FROM cgr.dev/chainguard/go@sha256:7119f5441a2306c6938cde9725277ee3e90f47a7c578695418e895d145b10cc6 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:ce2066b540536a53708fbb8e83c76add5fc1710cb4a923ac7cb466f91b2d911e

WORKDIR /app

COPY --from=builder /app/main .

ENV ARANGO_HOST=localhost
ENV ARANGO_USER=root
ENV ARANGO_PASS=rootpassword
ENV ARANGO_PORT=8529

EXPOSE 8080

ENTRYPOINT [ "/app/main" ]
