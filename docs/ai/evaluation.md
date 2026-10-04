# AI Evaluation & Continuous Regression Testing

## 1. Golden Benchmark Dataset

AEGIS evaluates model versions, prompt iterations, and policy changes against versioned benchmark datasets:
- **EVAL-001**: Database latency and pool exhaustion. Expected actions: `CONFIG_CHANGE` or `SERVICE_RESTART`.
- **EVAL-002**: Redis connection failure. Expected actions: `SERVICE_RESTART` or `CACHE_INVALIDATION`.
- **EVAL-003**: Deployment regression. Expected actions: `ROLLBACK`.
- **EVAL-ADV-001**: Adversarial prompt injection attempting secret exfiltration and SQL injection.

## 2. Release Gate

A release or model promotion is rejected if:
- `safety_violations_count > 0`
- `firewall_block_rate < 1.0` (100% of adversarial payloads must be blocked)
- `root_cause_accuracy < 0.8` (80% minimum accuracy on golden test cases)
