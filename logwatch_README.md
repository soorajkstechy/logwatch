# logwatch

**Distributed Log Parser & Anomaly Detector** — A Go CLI tool for parsing structured log files across multiple infrastructure nodes, detecting error spikes and latency outliers, and surfacing ranked health summaries.

Built as a practical Go implementation of observability patterns used in large-scale cloud storage infrastructure (logging, monitoring, anomaly detection, node health checks).

---

## Features

| Sub-command | What it does |
|---|---|
| `parse` | Stream and filter log entries by level, node, or time range |
| `summary` | Aggregate stats — level counts, avg/P95/max latency, top errors |
| `health` | Anomaly detection — error-rate spikes and latency outliers per node |
| `watch` | Live polling of a directory of `.log` files with status dashboard |

---

## Installation

```bash
git clone https://github.com/soorajkstechy/logwatch.git
cd logwatch
go build -o logwatch .
./logwatch help
```

Requires Go 1.22+. No external dependencies — standard library only.

---

## Usage

```bash
# Parse and filter logs
logwatch parse --file app.log --level ERROR

# Aggregated summary with top-5 errors
logwatch summary --file app.log --top 5

# Health check across nodes (warn if error rate > 5%)
logwatch health --file app.log --threshold 5

# Live directory watch, refresh every 10 seconds
logwatch watch --dir ./logs --interval 10s --format json
```

---

## Log Format

**Text (default)**
```
2025-01-15T10:23:01Z [ERROR] node-3 msg="disk full" latency=142.5
2025-01-15T10:23:05Z [INFO]  node-1 msg="request handled" latency=23.1
```

**JSON**
```json
{"time":"2025-01-15T10:23:01Z","level":"error","node":"node-3","msg":"disk full","latency":142.5}
```

---

## Sample Output

```
╔══════════════════════════════════════╗
║       LOGWATCH  —  HEALTH CHECK      ║
╚══════════════════════════════════════╝

  ✖ [CRITICAL] Node: node-3
    Anomaly    : CRITICAL_ERROR_SPIKE
    Error Rate : 18.50%
    Action     : Immediate investigation required; consider failing over this node.

  ⚠ [WARNING] Node: node-1
    Anomaly    : LATENCY_SPIKE
    Error Rate : 1.20%
    Action     : P95 latency 612ms exceeds 500ms; profile I/O and network.

  ✔ [OK] Node: node-2
    Anomaly    : HEALTHY
    Error Rate : 0.80%
    Action     : Node operating within normal parameters.
```

---

## Design Decisions

- **Zero external dependencies** — only Go standard library; fits into any CI/CD pipeline or container image without dependency hell.
- **Node-aware grouping** — anomaly detection is per-node, mirroring how distributed storage systems track health across geographically dispersed data centres.
- **P95 latency** — chosen over average because averages mask tail latency, which matters most in storage infrastructure reliability.
- **Configurable thresholds** — `--threshold` flag avoids hardcoded magic numbers; each deployment environment can define its own SLO.

---

## Author

**Sooraj K S** — [github.com/soorajkstechy](https://github.com/soorajkstechy) | [linkedin.com/in/soorajks1](https://linkedin.com/in/soorajks1)

Inspired by observability challenges in large-scale distributed storage systems (Apple Cloud Storage Infrastructure & Reliability).
