package rules

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/siem/internal/parser"
)

type RuleResult struct {
	Type     string  `json:"type"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
	Message  string  `json:"message"`
}

type RuleEngine struct {
	failedLogins map[string]int // IP → count
	lastReset    time.Time
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		failedLogins: make(map[string]int),
		lastReset:    time.Now(),
	}
}

func (r *RuleEngine) Check(log parser.NormalizedLog) []RuleResult {
	r.resetSlidingWindow()

	var results []RuleResult

	switch log.EventType {
	case "ssh_failed":
		results = append(results, r.checkSSHBruteforce(log)...)
	case "ssh_success":
		results = append(results, r.checkSuspiciousSuccess(log)...)
	case "sudo":
		results = append(results, r.checkSudoAbuse(log)...)
	case "metrics":
		results = append(results, r.checkResourceExhaustion(log)...)
	}

	return results
}

func (r *RuleEngine) checkSSHBruteforce(log parser.NormalizedLog) []RuleResult {
	if log.SrcIP == "" {
		return nil
	}

	r.failedLogins[log.SrcIP]++

	count := r.failedLogins[log.SrcIP]
	if count >= 5 {
		return []RuleResult{{
			Type:     "SSH_BRUTEFORCE",
			Severity: "HIGH",
			Score:    float64(count) / 5.0,
			Message:  fmt.Sprintf("SSH bruteforce from %s: %d attempts", log.SrcIP, count),
		}}
	}

	return nil
}

func (r *RuleEngine) checkSuspiciousSuccess(log parser.NormalizedLog) []RuleResult {
	suspiciousUsers := []string{"root", "admin", "test", "ubuntu", "pi"}
	for _, user := range suspiciousUsers {
		if strings.Contains(strings.ToLower(log.User), user) {
			return []RuleResult{{
				Type:     "SUSPICIOUS_LOGIN",
				Severity: "MEDIUM",
				Score:    0.8,
				Message:  fmt.Sprintf("Suspicious user login: %s from %s", log.User, log.SrcIP),
			}}
		}
	}
	return nil
}

func (r *RuleEngine) checkSudoAbuse(log parser.NormalizedLog) []RuleResult {
	if log.User != "root" && strings.Contains(log.Message, "COMMAND=/bin/sh") {
		return []RuleResult{{
			Type:     "SUDO_PRIVESC",
			Severity: "HIGH",
			Score:    0.95,
			Message:  fmt.Sprintf("Potential sudo priv esc by %s", log.User),
		}}
	}
	return nil
}

func (r *RuleEngine) checkResourceExhaustion(log parser.NormalizedLog) []RuleResult {
	if cpu, mem := extractMetrics(log.Message); cpu > 90 || mem > 90 {
		return []RuleResult{{
			Type:     "RESOURCE_EXHAUSTION",
			Severity: "MEDIUM",
			Score:    math.Max(cpu, mem) / 100.0,
			Message:  fmt.Sprintf("High resource usage: CPU %.1f%% MEM %.1f%%", cpu, mem),
		}}
	}
	return nil
}

func (r *RuleEngine) resetSlidingWindow() {
	if time.Since(r.lastReset) > 5*time.Minute {
		r.failedLogins = make(map[string]int)
		r.lastReset = time.Now()
	}
}
