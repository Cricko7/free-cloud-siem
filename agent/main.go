// agent/main.go - FIXED VERSION
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ServerURL string   `yaml:"server_url"`
	LogFiles  []string `yaml:"log_files"`
	BatchSize int      `yaml:"batch_size"`
}

type LogEntry struct {
	Timestamp string `json:"ts"`
	Host      string `json:"host"`
	Source    string `json:"source"`
	Message   string `json:"msg"`
	Level     string `json:"level"`
	Pid       int    `json:"pid,omitempty"`
}

type Agent struct {
	config Config
	host   string
	conn   *websocket.Conn
	logCh  chan LogEntry
	stopCh chan struct{}
}

func main() {
	configPath := flag.String("config", "config.yaml", "config file")
	flag.Parse()

	agent, err := NewAgent(*configPath)
	if err != nil {
		log.Fatal("Failed to create agent:", err)
	}
	defer agent.Close() // ✅ Теперь работает!

	log.Printf("SIEM Agent started on %s -> %s", agent.host, agent.config.ServerURL)
	agent.Run()
}

func NewAgent(configPath string) (*Agent, error) {
	host, _ := os.Hostname()

	var config Config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	yaml.Unmarshal(data, &config)

	if config.ServerURL == "" {
		config.ServerURL = "ws://localhost:8080/ws"
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if len(config.LogFiles) == 0 {
		config.LogFiles = []string{"/var/log/auth.log", "/var/log/syslog"}
	}

	dialer := websocket.DefaultDialer
	conn, _, err := dialer.Dial(config.ServerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	return &Agent{
		config: config,
		host:   host,
		conn:   conn,
		logCh:  make(chan LogEntry, 1000),
		stopCh: make(chan struct{}),
	}, nil
}

func (a *Agent) Run() {
	// Запуск коллекторов логов
	for _, logFile := range a.config.LogFiles {
		go a.collectLogs(logFile)
	}

	// Периодическая отправка метрик
	go a.collectMetrics()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Batch sender
	go a.batchSender()

	<-sigCh
	a.Stop()
}

func (a *Agent) collectLogs(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("Failed to open %s: %v", filename, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-a.stopCh:
			return
		default:
			line := scanner.Text()
			level := parseLevel(line)
			entry := LogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Host:      a.host,
				Source:    filename,
				Message:   line,
				Level:     level,
			}
			a.logCh <- entry
		}
	}
}

func (a *Agent) collectMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			entry := LogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Host:      a.host,
				Source:    "metrics",
				Message:   fmt.Sprintf("CPU:%.1f%% MEM:%.1f%%", getCPU(), getMem()),
				Level:     "info",
			}
			select {
			case a.logCh <- entry:
			case <-a.stopCh:
				return
			}
		case <-a.stopCh:
			return
		}
	}
}

func (a *Agent) batchSender() {
	batch := make([]LogEntry, 0, a.config.BatchSize)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case entry := <-a.logCh:
			batch = append(batch, entry)
			if len(batch) >= a.config.BatchSize {
				a.sendBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				a.sendBatch(batch)
				batch = batch[:0]
			}
		case <-a.stopCh:
			if len(batch) > 0 {
				a.sendBatch(batch)
			}
			return
		}
	}
}

func (a *Agent) sendBatch(batch []LogEntry) {
	data, _ := json.Marshal(map[string]interface{}{
		"type":  "logs",
		"host":  a.host,
		"batch": batch,
	})

	if err := a.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("Send failed: %v", err)
		// Reconnect logic можно добавить позже
	}
}

func (a *Agent) Stop() {
	close(a.stopCh)
	if a.conn != nil {
		a.conn.Close()
	}
	log.Println("Agent stopped")
}

// ✅ Добавлен недостающий метод
func (a *Agent) Close() {
	a.Stop()
	log.Println("Agent closed gracefully")
}

func parseLevel(line string) string {
	line = strings.ToLower(line)
	switch {
	case strings.Contains(line, "error"), strings.Contains(line, "failed"):
		return "error"
	case strings.Contains(line, "warn"), strings.Contains(line, "warning"):
		return "warn"
	case strings.Contains(line, "auth"), strings.Contains(line, "login"):
		return "security"
	default:
		return "info"
	}
}

func getCPU() float64 { return 12.5 } // Заглушка
func getMem() float64 { return 67.3 } // Заглушка
