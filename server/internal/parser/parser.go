package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
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

var (
	sshFailedRe   = regexp.MustCompile(`Failed password|invalid user (.+?) from ([\d.]+)(?::(\d+))?`)
	authSuccessRe = regexp.MustCompile(`Accepted password|Accepted publickey for (.+?) from ([\d.]+)`)
	sudoRe        = regexp.MustCompile(`sudo: +(.+?) : ([\w-]+) ; TTY=pts/(\d+) ; PWD=`)
	cpuMemRe      = regexp.MustCompile(`CPU:([\d.]+)% MEM:([\d.]+)%`)
)

func ParseLog(source, line string) NormalizedLog {
	log := NormalizedLog{
		Source:  source,
		Message: strings.TrimSpace(line),
		Raw:     line,
		Level:   parseLevel(line),
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
		log.Level = "info"
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
	if match := cpuMemRe.FindStringSubmatch(line); len(match) >= 3 {
		log.EventType = "metrics"
		log.Level = "info"
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
	case strings.Contains(l, "warn", "warning"):
		return "warn"
	case strings.Contains(l, "auth"), strings.Contains(l, "sudo"), strings.Contains(l, "password"):
		return "security"
	default:
		return "info"
	}
}
