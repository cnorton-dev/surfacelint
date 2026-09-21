# Scoring Model

SurfaceLint v0.1 starts each assessment at 100 points and subtracts deterministic penalties for warning and failed findings.

| Severity | Failed | Warning |
| --- | ---: | ---: |
| High | 12 | 6 |
| Medium | 7 | 4 |
| Low | 3 | 2 |

Passed and informational findings do not reduce the score. Scores are clamped at zero.

## Why the score is secondary

The score is a summary, not a risk prediction or compliance grade. The evidence and remediation attached to individual findings are more important than the number itself.

The scoring model is explicitly marked pre-1.0 and may change as checks are calibrated against real-world configurations.
