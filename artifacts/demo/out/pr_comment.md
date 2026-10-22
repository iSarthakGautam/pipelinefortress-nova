## PipelineFortress AI triage (draft, a human decides)

**6** findings -> **5** clusters -> **4** true positive, **0** false positive, **1** need a human. **3** are P1. Validator rejected claims in **0** cluster(s).

### True positives
| Priority | Where | Rule | Suggested fix |
|---|---|---|---|
| P1 | `apps/vulnshop-api/config.py:12` | aws-access-key | Replace the hardcoded AWS access key with an environment variable or a secure storage solution. This will prevent the key from being committed to source control and reduce the risk of it being exposed |
| P1 | `pom.xml:34` | CVE-2021-44228 | Upgrade log4j-core to 2.17.0 or later. |
| P2 | `apps/vulnshop-api/routes/search.py:42` | sql-injection | Fix this by using parameterized queries or escaping the user input. For example, you can use the 'sqlite3' module's 'execute()' method to execute parameterized queries. |
| P3 | `infra/k8s/deployment.yaml:20` | CKV_K8S_40 | To fix this, ensure that the securityContext in deployment.yaml is set to runAsNonRoot: true. This will prevent the container from running as root. |

### Needs a human
| Where | Why |
|---|---|
| `apps/vulnshop-api/routes/pay.py:3` | Possible prompt injection in scanner-supplied text; model skipped. Human triage required. |

<sub>Model `llama3:latest@​sha256:365c0bd3c000`. AI output is advisory: it cannot merge or change anything. Every claim above was checked by `ai/validate.py`; replay log in `artifacts/llm_trace/`.</sub>
