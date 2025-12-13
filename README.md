# free-cloud-siem
---

---

## Общая структура

```
[Cloud VMs: AWS EC2/GCP GCE/Azure VM]
       ↓ Agents (Go binary, 5MB)
    ┌─────────────────┐
    │ WebSocket/gRPC  │ ← TLS + Mutual Auth
    └─────────┬───────┘
              ↓
[SIEM Server: Go + PostgreSQL + Redis]
    ┌──────────┼──────────┐
    │ Analyzer │ Storage  │
    └────┬─────┼────┬─────┘
         ↓     ↓    ↓
[Rules Engine] [JSONB Logs] [Alerts Queue]
         ↓                 ↓
    ┌──────────────┐    ↓
    │ WebSocket    │ ←──┘ Real-time
    │ Hub (live)   │
    └──────┬───────┘
           ↓
[React Dashboard: Logs/Alerts/Charts]
       ↓ API REST
[Mobile/CLI: Optional]
```

## Древо проекта

```
free-cloud-siem/
├── README.md                    # 🚀 Quickstart + API docs
├── docker-compose.yml           # 🐳 Local dev/prod stack
├── docker-compose.monitoring.yml # 📊 Prometheus/Grafana
├── .env.example                 # 🔑 Secrets template
├── .gitignore
├── Makefile                     # make dev/prod/deploy
│
├── agent/                       # 🛡️ 5MB binary для VM
│   ├── go.mod / go.sum
│   ├── main.go                  # Entry point
│   ├── collector/               # 📡 Data collection
│   │   ├── logs.go             # tail -f /var/log/*, journalctl
│   │   ├── metrics.go          # CPU/Mem/Net/Disk (telegraf-like)
│   │   ├── audit.go            # auditd events (Linux security)
│   │   └── cloud.go            # AWS CloudWatch/GCP Logging
│   ├── sender/                  # 🚀 Transport layer
│   │   ├── websocket.go        # ws://server/ws (fallback HTTP/2)
│   │   └── grpc.go             # High-load: gRPC protobuf
│   ├── crypto/                  # 🔒 Security
│   │   └── tls.go              # mTLS cert rotation
│   ├── config.yaml             # Server URL, log filters, batch size
│   ├── Dockerfile              # Multi-arch: amd64/arm64
│   └── deploy/                 # systemd + Ansible
│       ├── siem-agent.service
│       └── install.sh
│
├── server/                      # ⚙️ Core engine (Go 1.23)
│   ├── go.mod / go.sum
│   ├── cmd/server/main.go      # HTTP + WS server
│   ├── internal/
│   │   ├── api/                # 🌐 REST + OpenAPI
│   │   │   ├── v1/
│   │   │   │   ├── logs.go     # GET /logs?host=ec2-1&from=2025-12-13
│   │   │   │   ├── alerts.go   # POST /alerts/ack, GET /alerts/active
│   │   │   │   └── rules.go    # GET /rules, POST /rules/test
│   │   │   └── health.go       # /healthz + metrics
│   │   ├── storage/            # 💾 PostgreSQL + Redis
│   │   │   ├── db.go           # GORM + connection pool
│   │   │   ├── models.go       # LogEntry, Alert, Rule (JSONB)
│   │   │   └── migrations/     # 001_init.sql, 002_indexes.sql
│   │   ├── analyzer/           # 🧠 Detection engine
│   │   │   ├── rules.go        # Sigma/regex/YARA rules
│   │   │   ├── anomalies.go    # Statistical anomaly (z-score)
│   │   │   └── correlation.go  # Multi-event rules (brute-force)
│   │   ├── websocket/          # 📡 Real-time hub
│   │   │   └── hub.go          # Broadcast alerts/logs
│   │   └── queue/              # 📋 Async processing
│   │       ├── redis.go        # Redis Streams (alerts)
│   │       └── kafka.go        # Scale >1000 agents
│   ├── pkg/
│   │   ├── logger/             # Structured logging (zerolog)
│   │   └── parser/             # Log parsing (nginx/apache/syslog)
│   └── Dockerfile
│
├── dashboard/                   # 🎨 React 19 + Vite
│   ├── package.json            # React, TanStack Query, Recharts
│   ├── vite.config.js
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   │   ├── LogsTable.jsx   # Real-time table (TanStack)
│   │   │   ├── AlertsBoard.jsx # Active/critical alerts
│   │   │   ├── HostMetrics.jsx # CPU/Net charts (Recharts)
│   │   │   └── RuleEditor.jsx  # Visual Sigma rule builder
│   │   ├── hooks/
│   │   │   ├── useLogs.js      # REST + WS streaming
│   │   │   └── useAlerts.js
│   │   └── api/                # API clients (axios)
│   └── Dockerfile
│
├── k8s/                         # ☸️ Production (optional)
│   ├── helm/
│   │   ├── Chart.yaml
│   │   ├── values.yaml         # Replicas, resources
│   │   └── templates/
│   └── manifests/
│
├── scripts/                     # 🔧 Automation
│   ├── deploy-agent.sh         # scp + systemd enable
│   ├── migrate-db.sql          # psql migrations
│   ├── test-attacks.sh         # nmap/sshd-brute для теста
│   └── backup-restore.sh       # pg_dump + S3
│
└── monitoring/                  # 📈 Observability
    ├── docker-compose.yml
    ├── prometheus.yml
    └── grafana/
        └── dashboards/siem.json
```

## Data Flow

```
1. Agent: tail -f /var/log/auth.log → JSON batch (10s)
2. WS → Server: /ws/ingest → Redis Stream
3. Worker: Parse → Match Rules → PostgreSQL JSONB
4. Alert → WS Hub → React Dashboard (real-time)
5. API: Query logs → Full-text search + tsrange
```

## Fast start

```
git clone <repo> && cd siem-system
cp .env.example .env
docker-compose up -d postgres redis server
cd agent && go mod tidy && go build -o agent
./agent  # Логи полетели!
cd ../dashboard && npm i && npm run dev
```

---

