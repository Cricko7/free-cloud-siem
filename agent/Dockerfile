FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
ARG TARGETOS TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o siem-agent main.go

FROM scratch
COPY --from=builder /app/siem-agent /siem-agent
ENTRYPOINT ["/siem-agent"]
