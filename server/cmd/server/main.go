package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type NormalizedLog struct {
	Timestamp time.Time `json:"ts"`
	Host      string    `json:"host"`
	Source    string    `json:"source"`
	Message   string    `json:"msg"`
	Level     string    `json:"level"`
	EventType string    `json:"event_type"`
	SrcIP     string    `json:"src_ip"`
	DstPort   string    `json:"dst_port"`
	User      string    `json:"user"`
	Pid       int       `json:"pid"`
	Raw       string    `json:"raw"`
}

type AlertV2 struct {
	ID        uint          `json:"id"`
	Rule      string        `json:"rule"`
	Severity  string        `json:"severity"`
	Score     float64       `json:"score"`
	Message   string        `json:"message"`
	Log       NormalizedLog `json:"log"`
	Timestamp time.Time     `json:"alert_ts"`
}

type LegacyLogEntry struct {
	Timestamp string `json:"ts"`
	Host      string `json:"host"`
	Source    string `json:"source"`
	Message   string `json:"msg"`
	Level     string `json:"level"`
}

type Storage struct {
	normalizedLogs []NormalizedLog `json:"-"`
	alertsV2       []AlertV2       `json:"-"`
	mu             sync.RWMutex
}

var (
	storage    = &Storage{}
	upgrader   = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ruleEngine = NewRuleEngine()

	// Регулярки для парсинга
	sshFailedRe   = regexp.MustCompile(`Failed password|invalid user (.+?) from ([\d.]+)(?::(\d+))?`)
	authSuccessRe = regexp.MustCompile(`Accepted password|Accepted publickey for (.+?) from ([\d.]+)`)
	sudoRe        = regexp.MustCompile(`sudo: +(.+?) : ([\w-]+) ; TTY=pts/(\d+) ; PWD=`)
	cpuMemRe      = regexp.MustCompile(`CPU:([\d.]+)% MEM:([\d.]+)%`)
)

type RuleEngine struct {
	failedLogins map[string]int
	lastReset    time.Time
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		failedLogins: make(map[string]int),
		lastReset:    time.Now(),
	}
}

func (r *RuleEngine) Check(log NormalizedLog) []AlertV2 {
	r.resetSlidingWindow()
	var alerts []AlertV2

	switch log.EventType {
	case "ssh_failed":
		if alerts := r.checkSSHBruteforce(log); len(alerts) > 0 {
			alerts = append(alerts, alerts...)
		}
	case "ssh_success":
		if alerts := r.checkSuspiciousSuccess(log); len(alerts) > 0 {
			alerts = append(alerts, alerts...)
		}
	case "sudo":
		if alerts := r.checkSudoAbuse(log); len(alerts) > 0 {
			alerts = append(alerts, alerts...)
		}
	case "metrics":
		if alerts := r.checkResourceExhaustion(log); len(alerts) > 0 {
			alerts = append(alerts, alerts...)
		}
	}

	return alerts
}

func (r *RuleEngine) checkSSHBruteforce(log NormalizedLog) []AlertV2 {
	if log.SrcIP == "" {
		return nil
	}
	r.failedLogins[log.SrcIP]++

	if count := r.failedLogins[log.SrcIP]; count >= 5 {
		return []AlertV2{{
			Rule:      "SSH_BRUTEFORCE",
			Severity:  "HIGH",
			Score:     float64(count) / 10.0,
			Message:   fmt.Sprintf("SSH bruteforce %s: %d attempts", log.SrcIP, count),
			Log:       log,
			Timestamp: time.Now(),
		}}
	}
	return nil
}

func (r *RuleEngine) checkSuspiciousSuccess(log NormalizedLog) []AlertV2 {
	suspicious := []string{"root", "admin", "test", "ubuntu", "pi"}
	for _, user := range suspicious {
		if strings.Contains(strings.ToLower(log.User), user) {
			return []AlertV2{{
				Rule:      "SUSPICIOUS_LOGIN",
				Severity:  "MEDIUM",
				Score:     0.8,
				Message:   fmt.Sprintf("Suspicious login %s from %s", log.User, log.SrcIP),
				Log:       log,
				Timestamp: time.Now(),
			}}
		}
	}
	return nil
}

func (r *RuleEngine) checkSudoAbuse(log NormalizedLog) []AlertV2 {
	if log.User != "root" && strings.Contains(log.Message, "/bin/sh") {
		return []AlertV2{{
			Rule:      "SUDO_PRIVESC",
			Severity:  "HIGH",
			Score:     0.95,
			Message:   fmt.Sprintf("Sudo priv esc attempt by %s", log.User),
			Log:       log,
			Timestamp: time.Now(),
		}}
	}
	return nil
}

func (r *RuleEngine) checkResourceExhaustion(log NormalizedLog) []AlertV2 {
	if cpu, mem := extractMetrics(log.Message); cpu > 90 || mem > 90 {
		return []AlertV2{{
			Rule:      "RESOURCE_EXHAUSTION",
			Severity:  "MEDIUM",
			Score:     math.Max(cpu, mem) / 100.0,
			Message:   fmt.Sprintf("High resources: CPU %.1f%% MEM %.1f%%", cpu, mem),
			Log:       log,
			Timestamp: time.Now(),
		}}
	}
	return nil
}

func extractMetrics(msg string) (float64, float64) {
	match := cpuMemRe.FindStringSubmatch(msg)
	if len(match) == 3 {
		cpu, _ := strconv.ParseFloat(match[1], 64)
		mem, _ := strconv.ParseFloat(match[2], 64)
		return cpu, mem
	}
	return 0, 0
}

func (r *RuleEngine) resetSlidingWindow() {
	if time.Since(r.lastReset) > 5*time.Minute {
		r.failedLogins = make(map[string]int)
		r.lastReset = time.Now()
	}
}

func ParseLog(source, host, line string) NormalizedLog {
	log := NormalizedLog{
		Host:      host,
		Source:    source,
		Message:   strings.TrimSpace(line),
		Raw:       line,
		Timestamp: time.Now().UTC(),
		Level:     parseLevel(line),
	}

	// SSH Failed
	if match := sshFailedRe.FindStringSubmatch(line); len(match) >= 3 {
		log.EventType = "ssh_failed"
		log.User = match[1]
		log.SrcIP = match[2]
		if len(match) > 3 && match[3] != "" {
			port, _ := strconv.Atoi(match[3])
			log.DstPort = strconv.Itoa(port)
		}
		return log
	}

	// SSH Success
	if match := authSuccessRe.FindStringSubmatch(line); len(match) >= 3 {
		log.EventType = "ssh_success"
		log.User = match[1]
		log.SrcIP = match[2]
		return log
	}

	// Sudo
	if match := sudoRe.FindStringSubmatch(line); len(match) >= 4 {
		log.EventType = "sudo"
		log.User = match[1]
		log.Pid, _ = strconv.Atoi(match[3])
		return log
	}

	// Metrics
	if cpuMemRe.MatchString(line) {
		log.EventType = "metrics"
		return log
	}

	log.EventType = "generic"
	return log
}

func parseLevel(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "error"), strings.Contains(l, "failed"):
		return "error"
	case strings.Contains(l, "warn"):
		return "warn"
	case strings.Contains(l, "auth"), strings.Contains(l, "sudo"), strings.Contains(l, "password"):
		return "security"
	default:
		return "info"
	}
}

func main() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:3000", "http://localhost"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		AllowCredentials: true,
	}))

	r.GET("/ws", wsHandler)
	r.GET("/logs", logsHandler)
	r.GET("/logs/normalized", normalizedLogsHandler)
	r.GET("/alerts", alertsHandler)
	r.GET("/alerts/v2", alertsV2Handler)
	r.GET("/health", healthHandler)
	r.GET("/", dashboardHandler)

	log.Println("🚀 SIEM Server v2.0: http://localhost:8080")
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
		Type  string           `json:"type"`
		Host  string           `json:"host"`
		Batch []LegacyLogEntry `json:"batch"`
	}

	if err := json.Unmarshal(data, &batch); err != nil {
		log.Printf("JSON parse error: %v", err)
		return
	}

	storage.mu.Lock()
	for i := range batch.Batch {
		// ✅ НОРМАЛИЗАЦИЯ ЛОГОВ
		normLog := ParseLog(batch.Batch[i].Source, batch.Host, batch.Batch[i].Message)

		storage.normalizedLogs = append(storage.normalizedLogs, normLog)
		if len(storage.normalizedLogs) > 10000 {
			storage.normalizedLogs = storage.normalizedLogs[1000:]
		}

		// ✅ ПРОВЕРКА ПРАВИЛ v2.0
		alerts := ruleEngine.Check(normLog)
		for _, alert := range alerts {
			storage.alertsV2 = append(storage.alertsV2, alert)
			if len(storage.alertsV2) > 1000 {
				storage.alertsV2 = storage.alertsV2[100:]
			}
			log.Printf("🔴 ALERT [%s] %.2f: %s", alert.Severity, alert.Score, alert.Message)
		}
	}
	storage.mu.Unlock()

	conn.WriteMessage(websocket.TextMessage, []byte("OK"))
	log.Printf("💾 Saved %d normalized logs from %s", len(batch.Batch), batch.Host)
}

func normalizedLogsHandler(c *gin.Context) {
	storage.mu.RLock()
	logs := make([]NormalizedLog, len(storage.normalizedLogs))
	copy(logs, storage.normalizedLogs)
	storage.mu.RUnlock()

	logsToSend := logs
	if len(logsToSend) > 100 {
		logsToSend = logsToSend[len(logsToSend)-100:]
	}
	c.JSON(200, gin.H{"logs": logsToSend})
}

func alertsV2Handler(c *gin.Context) {
	storage.mu.RLock()
	alerts := make([]AlertV2, len(storage.alertsV2))
	copy(alerts, storage.alertsV2)
	storage.mu.RUnlock()

	alertsToSend := alerts
	if len(alertsToSend) > 50 {
		alertsToSend = alertsToSend[len(alertsToSend)-50:]
	}
	c.JSON(200, gin.H{"alerts": alertsToSend})
}

func logsHandler(c *gin.Context) {
	// Legacy endpoint
	storage.mu.RLock()
	var legacyLogs []LegacyLogEntry
	for _, log := range storage.normalizedLogs {
		legacyLogs = append(legacyLogs, LegacyLogEntry{
			Timestamp: log.Timestamp.Format(time.RFC3339),
			Host:      log.Host,
			Source:    log.Source,
			Message:   log.Message,
			Level:     log.Level,
		})
	}
	storage.mu.RUnlock()

	if len(legacyLogs) > 100 {
		legacyLogs = legacyLogs[len(legacyLogs)-100:]
	}
	c.JSON(200, gin.H{"logs": legacyLogs})
}

func alertsHandler(c *gin.Context) {
	// Legacy alerts
	c.JSON(200, gin.H{"alerts": []interface{}{}})
}

func healthHandler(c *gin.Context) {
	stats := gin.H{
		"status":             "healthy",
		"normalized_logs":    len(storage.normalizedLogs),
		"alerts_v2":          len(storage.alertsV2),
		"active_bruteforces": len(ruleEngine.failedLogins),
	}
	c.JSON(200, stats)
}

func dashboardHandler(c *gin.Context) {
	html := `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>SIEM v2.0 Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="p-8 bg-gray-900 text-white font-mono">
<h1 class="text-4xl mb-8">[SIEM v2.0] Production Dashboard</h1>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
<div>
<h2 class="text-2xl mb-4">[LOGS] <span id="logCount" class="bg-blue-600 px-3 py-1 rounded">0</span></h2>
<pre id="logs" class="bg-gray-800 p-4 h-96 overflow-auto border rounded-lg text-xs"></pre>
</div>
<div>
<h2 class="text-2xl mb-4">[ALERTS v2] <span id="alertCount" class="bg-red-600 px-3 py-1 rounded">0</span></h2>
<pre id="alerts" class="bg-red-900/50 p-4 h-96 overflow-auto border rounded-lg text-xs"></pre>
</div></div>
<script>
async function refresh() {
	try {
		const logs=await(await fetch('/logs/normalized')).json();
		const alerts=await(await fetch('/alerts/v2')).json();
		const health=await(await fetch('/health')).json();
		document.getElementById('logs').textContent=JSON.stringify(logs.logs||[],null,2);
		document.getElementById('alerts').textContent=JSON.stringify(alerts.alerts||[],null,2);
		document.getElementById('logCount').textContent=logs.logs?.length||0;
		document.getElementById('alertCount').textContent=alerts.alerts?.length||0;
		document.title='SIEM v2.0 | '+health.normalized_logs+' logs | '+health.alerts_v2+' alerts';
	} catch(e) {console.error(e);}
}
refresh();setInterval(refetch,2000);
</script></body></html>`
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Data(200, "text/html; charset=utf-8", []byte(html))
}
