// logwatch — a distributed log parser and anomaly detector
// Author  : Sooraj K S  (github.com/soorajkstechy)
// Purpose : Parse structured log files across multiple nodes, detect anomalies
//           (error spikes, latency outliers), and surface a ranked summary —
//           inspired by infrastructure observability challenges in Apple Cloud.
//
// Usage:
//   logwatch parse   --file <path> [--format json|text] [--level ERROR|WARN|INFO]
//   logwatch watch   --dir  <path> [--interval 5s]
//   logwatch summary --file <path> [--top 10]
//   logwatch health  --file <path> [--threshold 5]

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─── Data types ───────────────────────────────────────────────────────────────

// LogEntry represents one parsed log line.
type LogEntry struct {
	Timestamp time.Time
	Level     string
	Node      string
	Message   string
	Latency   float64 // ms, 0 if not present
	Raw       string
}

// Stats holds aggregated metrics for a log file / node.
type Stats struct {
	Total      int
	ByLevel    map[string]int
	AvgLatency float64
	MaxLatency float64
	P95Latency float64
	ErrorRate  float64
	TopErrors  []string
}

// AnomalyReport is returned by the health sub-command.
type AnomalyReport struct {
	Node          string
	ErrorRate     float64
	LatencySpike  bool
	AnomalyType   string
	Severity      string
	Recommendation string
}

// ─── Parsing ─────────────────────────────────────────────────────────────────

// parseTextLine parses a plain-text log line in the format:
//   2025-01-15T10:23:01Z [ERROR] node-3 | msg="disk full" latency=142.5
func parseTextLine(line string) (LogEntry, bool) {
	entry := LogEntry{Raw: line}
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		return entry, false
	}
	ts, err := time.Parse(time.RFC3339, parts[0])
	if err != nil {
		return entry, false
	}
	entry.Timestamp = ts
	entry.Level = strings.Trim(parts[1], "[]")
	entry.Node = parts[2]
	rest := parts[3]

	// Extract msg
	if idx := strings.Index(rest, `msg="`); idx != -1 {
		start := idx + 5
		end := strings.Index(rest[start:], `"`)
		if end != -1 {
			entry.Message = rest[start : start+end]
		}
	}

	// Extract latency
	if idx := strings.Index(rest, "latency="); idx != -1 {
		val := strings.Fields(rest[idx+8:])
		if len(val) > 0 {
			if ms, e := strconv.ParseFloat(val[0], 64); e == nil {
				entry.Latency = ms
			}
		}
	}
	return entry, true
}

// parseJSONLine parses a JSON-formatted log line.
func parseJSONLine(line string) (LogEntry, bool) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return LogEntry{Raw: line}, false
	}
	entry := LogEntry{Raw: line}
	if v, ok := raw["time"].(string); ok {
		ts, err := time.Parse(time.RFC3339, v)
		if err == nil {
			entry.Timestamp = ts
		}
	}
	if v, ok := raw["level"].(string); ok {
		entry.Level = strings.ToUpper(v)
	}
	if v, ok := raw["node"].(string); ok {
		entry.Node = v
	}
	if v, ok := raw["msg"].(string); ok {
		entry.Message = v
	}
	if v, ok := raw["latency"].(float64); ok {
		entry.Latency = v
	}
	return entry, true
}

// loadEntries reads a file and returns all parseable log entries.
func loadEntries(path, format string) ([]LogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var (
			e  LogEntry
			ok bool
		)
		switch strings.ToLower(format) {
		case "json":
			e, ok = parseJSONLine(line)
		default:
			e, ok = parseTextLine(line)
		}
		if ok {
			entries = append(entries, e)
		}
	}
	return entries, scanner.Err()
}

// ─── Analysis ────────────────────────────────────────────────────────────────

// computeStats aggregates a slice of log entries into Stats.
func computeStats(entries []LogEntry) Stats {
	s := Stats{ByLevel: make(map[string]int)}
	latencies := []float64{}
	errMsgs := map[string]int{}

	for _, e := range entries {
		s.Total++
		s.ByLevel[e.Level]++
		if e.Latency > 0 {
			latencies = append(latencies, e.Latency)
			if e.Latency > s.MaxLatency {
				s.MaxLatency = e.Latency
			}
		}
		if e.Level == "ERROR" && e.Message != "" {
			errMsgs[e.Message]++
		}
	}

	// Average & P95 latency
	if len(latencies) > 0 {
		sum := 0.0
		for _, l := range latencies {
			sum += l
		}
		s.AvgLatency = sum / float64(len(latencies))
		sort.Float64s(latencies)
		p95idx := int(math.Ceil(0.95*float64(len(latencies)))) - 1
		if p95idx >= 0 && p95idx < len(latencies) {
			s.P95Latency = latencies[p95idx]
		}
	}

	// Error rate
	if s.Total > 0 {
		s.ErrorRate = 100.0 * float64(s.ByLevel["ERROR"]) / float64(s.Total)
	}

	// Top errors by frequency
	type kv struct {
		Key   string
		Count int
	}
	var sorted []kv
	for k, v := range errMsgs {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Count > sorted[j].Count })
	for i, item := range sorted {
		if i >= 5 {
			break
		}
		s.TopErrors = append(s.TopErrors, fmt.Sprintf("%dx %s", item.Count, item.Key))
	}

	return s
}

// detectAnomalies runs threshold-based anomaly detection.
func detectAnomalies(entries []LogEntry, errThreshold float64) []AnomalyReport {
	// Group by node
	byNode := map[string][]LogEntry{}
	for _, e := range entries {
		node := e.Node
		if node == "" {
			node = "unknown"
		}
		byNode[node] = append(byNode[node], e)
	}

	var reports []AnomalyReport
	for node, es := range byNode {
		st := computeStats(es)
		r := AnomalyReport{Node: node, ErrorRate: st.ErrorRate}

		switch {
		case st.ErrorRate >= errThreshold*2:
			r.AnomalyType = "CRITICAL_ERROR_SPIKE"
			r.Severity = "CRITICAL"
			r.Recommendation = "Immediate investigation required; consider failing over this node."
		case st.ErrorRate >= errThreshold:
			r.AnomalyType = "ERROR_RATE_HIGH"
			r.Severity = "WARNING"
			r.Recommendation = "Review recent deployments and disk/memory utilisation on this node."
		case st.P95Latency > 500:
			r.AnomalyType = "LATENCY_SPIKE"
			r.Severity = "WARNING"
			r.LatencySpike = true
			r.Recommendation = fmt.Sprintf("P95 latency %.0fms exceeds 500ms; profile I/O and network.", st.P95Latency)
		default:
			r.AnomalyType = "HEALTHY"
			r.Severity = "OK"
			r.Recommendation = "Node operating within normal parameters."
		}
		reports = append(reports, r)
	}
	sort.Slice(reports, func(i, j int) bool {
		order := map[string]int{"CRITICAL": 0, "WARNING": 1, "OK": 2}
		return order[reports[i].Severity] < order[reports[j].Severity]
	})
	return reports
}

// ─── Sub-commands ─────────────────────────────────────────────────────────────

func cmdParse(args []string) {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	file := fs.String("file", "", "Path to log file (required)")
	format := fs.String("format", "text", "Log format: json | text")
	level := fs.String("level", "", "Filter by log level (ERROR, WARN, INFO)")
	fs.Parse(args)

	if *file == "" {
		fmt.Fprintln(os.Stderr, "error: --file is required")
		os.Exit(1)
	}
	entries, err := loadEntries(*file, *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%-25s %-8s %-10s %s\n", "TIMESTAMP", "LEVEL", "NODE", "MESSAGE")
	fmt.Println(strings.Repeat("-", 80))
	for _, e := range entries {
		if *level != "" && !strings.EqualFold(e.Level, *level) {
			continue
		}
		ts := e.Timestamp.Format("2006-01-02T15:04:05Z")
		fmt.Printf("%-25s %-8s %-10s %s\n", ts, e.Level, e.Node, e.Message)
	}
}

func cmdSummary(args []string) {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	file := fs.String("file", "", "Path to log file (required)")
	format := fs.String("format", "text", "Log format: json | text")
	top := fs.Int("top", 5, "Number of top errors to show")
	fs.Parse(args)

	if *file == "" {
		fmt.Fprintln(os.Stderr, "error: --file is required")
		os.Exit(1)
	}
	entries, err := loadEntries(*file, *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	st := computeStats(entries)

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║        LOGWATCH  —  SUMMARY          ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Printf("  File          : %s\n", *file)
	fmt.Printf("  Total Entries : %d\n", st.Total)
	fmt.Println()
	fmt.Println("  Level Breakdown:")
	for _, lvl := range []string{"ERROR", "WARN", "INFO", "DEBUG"} {
		if c, ok := st.ByLevel[lvl]; ok {
			bar := strings.Repeat("█", c*20/max(st.Total, 1))
			fmt.Printf("    %-6s %4d  %s\n", lvl, c, bar)
		}
	}
	fmt.Println()
	fmt.Printf("  Error Rate    : %.2f%%\n", st.ErrorRate)
	fmt.Printf("  Avg Latency   : %.2f ms\n", st.AvgLatency)
	fmt.Printf("  P95 Latency   : %.2f ms\n", st.P95Latency)
	fmt.Printf("  Max Latency   : %.2f ms\n", st.MaxLatency)
	fmt.Println()
	if len(st.TopErrors) > 0 {
		fmt.Println("  Top Errors:")
		for i, e := range st.TopErrors {
			if i >= *top {
				break
			}
			fmt.Printf("    [%d] %s\n", i+1, e)
		}
	}
}

func cmdHealth(args []string) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	file := fs.String("file", "", "Path to log file (required)")
	format := fs.String("format", "text", "Log format: json | text")
	threshold := fs.Float64("threshold", 5.0, "Error-rate % threshold to trigger WARNING")
	fs.Parse(args)

	if *file == "" {
		fmt.Fprintln(os.Stderr, "error: --file is required")
		os.Exit(1)
	}
	entries, err := loadEntries(*file, *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	reports := detectAnomalies(entries, *threshold)

	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║       LOGWATCH  —  HEALTH CHECK      ║")
	fmt.Println("╚══════════════════════════════════════╝")
	for _, r := range reports {
		icon := map[string]string{"CRITICAL": "✖", "WARNING": "⚠", "OK": "✔"}[r.Severity]
		fmt.Printf("\n  %s [%s] Node: %s\n", icon, r.Severity, r.Node)
		fmt.Printf("    Anomaly    : %s\n", r.AnomalyType)
		fmt.Printf("    Error Rate : %.2f%%\n", r.ErrorRate)
		fmt.Printf("    Action     : %s\n", r.Recommendation)
	}
	fmt.Println()
}

func cmdWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	dir := fs.String("dir", ".", "Directory to watch for *.log files")
	interval := fs.Duration("interval", 5*time.Second, "Polling interval (e.g. 5s, 10s)")
	format := fs.String("format", "text", "Log format: json | text")
	fs.Parse(args)

	fmt.Printf("Watching %s every %v — press Ctrl+C to stop\n\n", *dir, *interval)
	for {
		files, _ := filepath.Glob(filepath.Join(*dir, "*.log"))
		for _, f := range files {
			entries, err := loadEntries(f, *format)
			if err != nil {
				continue
			}
			st := computeStats(entries)
			status := "OK"
			if st.ErrorRate >= 5 {
				status = "⚠ WARN"
			}
			if st.ErrorRate >= 10 {
				status = "✖ CRIT"
			}
			fmt.Printf("[%s] %-30s total=%-5d errors=%-4d err%%=%.1f%% p95=%.0fms\n",
				status, filepath.Base(f), st.Total, st.ByLevel["ERROR"],
				st.ErrorRate, st.P95Latency)
		}
		fmt.Println(strings.Repeat("-", 80))
		time.Sleep(*interval)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func printHelp() {
	fmt.Println(`logwatch — Distributed Log Parser & Anomaly Detector
Author  : Sooraj K S  (github.com/soorajkstechy/logwatch)

USAGE:
  logwatch <command> [flags]

COMMANDS:
  parse    Stream and filter log entries from a file
  summary  Show aggregated statistics (level counts, latency, top errors)
  health   Run anomaly detection across nodes with configurable thresholds
  watch    Continuously poll a directory of .log files and print live status

EXAMPLES:
  logwatch parse   --file app.log --level ERROR
  logwatch summary --file app.log --top 5
  logwatch health  --file app.log --threshold 5
  logwatch watch   --dir ./logs  --interval 10s --format json

FLAGS (global):
  --format   json | text  (default: text)
  --file     path to log file
  --dir      directory for watch sub-command`)
}

// ─── Entry point ─────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}
	cmd, rest := os.Args[1], os.Args[2:]
	switch cmd {
	case "parse":
		cmdParse(rest)
	case "summary":
		cmdSummary(rest)
	case "health":
		cmdHealth(rest)
	case "watch":
		cmdWatch(rest)
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printHelp()
		os.Exit(1)
	}
}
