# server/Dockerfile
FROM golang:1.23-alpine AS builder
COPY . /app
WORKDIR /app/cmd/server
RUN go build -o siem-server .

FROM alpine:latest
COPY --from=builder /app/cmd/server/siem-server .
EXPOSE 8080
CMD ["./siem-server"]
