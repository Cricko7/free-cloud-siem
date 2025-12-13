package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type LogEntry struct {
	Timestamp string `json:"ts"`
	Host      string `json:"host"`
	Source    string `json:"source"`
	Message   string `json:"msg"`
	Level     string `json:"level"`
}

type Storage struct {
	logs   []LogEntry
	alerts []Alert
	mu     sync.RWMutex
}

type Alert struct {
	Host     string `json:"host"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Ts       string `json:"ts"`
}

var storage = &Storage{}
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func main() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		AllowCredentials: true,
	}))

	r.GET("/ws", wsHandler)
	r.GET("/logs", logsHandler)
	r.GET("/alerts", alertsHandler)
	r.GET("/", dashboardHandler)

	log.Println("🚀 SIEM Server: http://localhost:8080")
	log.Fatal(r.Run(":8080"))
}

func wsHandler(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("WS error:", err)
		return
	}
	defer conn.Close()

	log.Printf("🟢 Agent %s connected", c.RemoteIP())

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		go handleLogs(conn, msg)
	}
}

func handleLogs(conn *websocket.Conn, data []byte) {
	var batch struct {
		Type  string     `json:"type"`
		Host  string     `json:"host"`
		Batch []LogEntry `json:"batch"`
	}

	if err := json.Unmarshal(data, &batch); err != nil {
		log.Printf("JSON parse error: %v", err)
		conn.WriteMessage(websocket.TextMessage, []byte("ERROR"))
		return
	}

	storage.mu.Lock()
	for i := range batch.Batch {
		batch.Batch[i].Timestamp = time.Now().UTC().Format(time.RFC3339)
		storage.logs = append(storage.logs, batch.Batch[i])
		if len(storage.logs) > 10000 {
			storage.logs = storage.logs[1000:]
		}
	}
	storage.mu.Unlock()

	checkRules(batch.Host, batch.Batch)
	conn.WriteMessage(websocket.TextMessage, []byte("OK"))
	log.Printf("💾 Saved %d logs from %s", len(batch.Batch), batch.Host)
}

func checkRules(host string, logs []LogEntry) {
	for _, logEntry := range logs {
		if logEntry.Level == "security" && strings.Contains(strings.ToLower(logEntry.Message), "failed password") {
			alert := Alert{
				Host:     host,
				Type:     "SSH_BRUTEFORCE",
				Severity: "HIGH",
				Message:  logEntry.Message,
				Ts:       logEntry.Timestamp,
			}
			storage.mu.Lock()
			storage.alerts = append(storage.alerts, alert)
			storage.mu.Unlock()

			log.Printf("🔴 ALERT: %s on %s: %s", alert.Type, host, alert.Message)
		}
	}
}

// ✅ ИСПРАВЛЕННЫЕ handlers
func logsHandler(c *gin.Context) {
	storage.mu.RLock()
	logs := make([]LogEntry, len(storage.logs))
	copy(logs, storage.logs)
	storage.mu.RUnlock()

	logsToSend := logs
	if len(logsToSend) > 100 {
		logsToSend = logsToSend[:100]
	}

	c.JSON(200, gin.H{"logs": logsToSend})
}

func alertsHandler(c *gin.Context) {
	storage.mu.RLock()
	alerts := make([]Alert, len(storage.alerts))
	copy(alerts, storage.alerts)
	storage.mu.RUnlock()

	alertsToSend := alerts
	if len(alertsToSend) > 50 {
		alertsToSend = alertsToSend[:50]
	}

	c.JSON(200, gin.H{"alerts": alertsToSend})
}

func dashboardHandler(c *gin.Context) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>SIEM Dashboard</title>
    <meta charset="UTF-8"> <!-- ✅ UTF-8 -->
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="p-8 bg-gray-900 text-white font-mono">
    <h1 class="text-4xl mb-8 font-bold text-white">🚨 SIEM Dashboard</h1>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div>
            <h2 class="text-2xl mb-4 flex items-center">
                📋 Recent Logs 
                <span id="logCount" class="ml-2 px-2 py-1 bg-blue-600 text-white rounded text-sm">0</span>
            </h2>
            <pre id="logs" class="bg-gray-800 p-4 h-96 overflow-auto text-sm font-mono border border-gray-700 rounded-lg"></pre>
        </div>
        <div>
            <h2 class="text-2xl mb-4 flex items-center">
                🚨 Alerts 
                <span id="alertCount" class="ml-2 px-2 py-1 bg-red-600 text-white rounded text-sm">0</span>
            </h2>
            <pre id="alerts" class="bg-red-900/50 p-4 h-96 overflow-auto text-sm font-mono border border-red-500 rounded-lg"></pre>
        </div>
    </div>
    <script>
        async function refresh() {
            try {
                const logsResp = await fetch('/logs');
                const alertsResp = await fetch('/alerts');
                const logs = await logsResp.json();
                const alerts = await alertsResp.json();
                
                document.getElementById('logs').textContent = JSON.stringify(logs.logs || [], null, 2);
                document.getElementById('alerts').textContent = JSON.stringify(alerts.alerts || [], null, 2);
                document.getElementById('logCount').textContent = logs.logs?.length || 0;
                document.getElementById('alertCount').textContent = alerts.alerts?.length || 0;
            } catch(e) {
                console.error('Refresh error:', e);
            }
        }
        refresh();
        setInterval(refresh, 2000);
    </script>
</body>
</html>`

	// ✅ UTF-8 заголовок!
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Data(200, "text/html; charset=utf-8", []byte(html))
}
