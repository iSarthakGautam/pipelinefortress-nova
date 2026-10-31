| Planted | Name | Expected | Matched as | Tools | Max severity |
|---|---|---|---|---|---|
| PLANT-001 | Raw String SQL Injection in Search | TRUE_POSITIVE | exact | bandit, semgrep | HIGH |
| PLANT-002 | Safe Parameterized User Query (Negative Control) | FALSE_POSITIVE | not flagged (good) | - | - |
| PLANT-003 | Hardcoded AWS Access Key | TRUE_POSITIVE | exact | semgrep | HIGH |
| PLANT-004 | Command Injection in Payment Receipt Logger | TRUE_POSITIVE | exact | bandit, semgrep | HIGH |
| PLANT-005 | Outdated Dependency with Known Prototype Pollution | TRUE_POSITIVE | **missed** | - | - |
| PLANT-006 | Container Base Image Uses Mutable Latest Tag & Runs as Root | TRUE_POSITIVE | exact | checkov, semgrep, trivy | HIGH |
| PLANT-007 | Kubernetes Container Runs as Root (runAsNonRoot: false) | TRUE_POSITIVE | exact | checkov, semgrep, trivy | HIGH |
| PLANT-008 | Reflected XSS via Unescaped Jinja Safe Filter | TRUE_POSITIVE | exact | semgrep | MEDIUM |
| PLANT-009 | Helmet Frameguard Anti-Clickjacking (Negative Control) | FALSE_POSITIVE | not flagged (good) | - | - |
| PLANT-010 | Second Raw-String SQL Injection (helper in search.py) | TRUE_POSITIVE | exact | bandit, semgrep | HIGH |
| PLANT-011 | Hardcoded AWS Secret Access Key | TRUE_POSITIVE | exact | bandit, semgrep | HIGH |
| PLANT-012 | Flask Debug Mode Enabled (Werkzeug debugger) | TRUE_POSITIVE | **missed** | - | - |

**Catch rate: 8/10 (80%)**; 8 on the exact line or package; **7/10 would block the merge** (>= HIGH). Negative controls flagged (false alarms): 0/2. Missed: PLANT-005, PLANT-012.
