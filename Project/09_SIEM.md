
# Capstone Project Outline  

## Đề tài 9: Xây dựng hệ thống SIEM trên cloud — tập trung logs từ OpenStack / AWS / Azure, tích hợp ELK / Splunk, phát hiện tấn công

**Mô tả ngắn:**  
Triển khai một hệ thống SIEM (Security Information and Event Management) để thu thập, chuẩn hoá, lưu trữ và phân tích logs/telemetry từ đa đám mây (OpenStack private lab + AWS/Azure public). Hệ thống tích hợp ELK (Elasticsearch/Logstash/Kibana) **hoặc** Splunk (tùy license), cung cấp pipeline ingest, enrichment, correlation, alerting, và khả năng phát hiện tấn công (rules + ML). Dự án bao gồm thiết kế kiến trúc, triển khai collector/forwarder, viết rules (Sigma), tích hợp threat intel, phát hiện & playbook phản ứng, đánh giá hiệu năng và operational metrics.

---

### 1. Đặt vấn đề (Problem Statement)

- Logs phân tán trên nhiều tầng (cloud provider logs, OS, application, network, IaC scanner outputs) khiến detection & response chậm.  
- Thiếu hệ thống tập trung dẫn đến blind spot, khó thực hiện threat hunting, và MTTR cao.  
- Mục tiêu: xây dựng SIEM reproducible cho môi trường học thuật — hỗ trợ ingest đa nguồn, correlation, alerting real‑time, và playbook phản ứng.

---

### 2. Mục tiêu dự án (Objectives)

- Triển khai ELK stack (OpenSearch + Logstash/Beats + Kibana) hoặc Splunk (được phép) trên cloud/lab.  
- Thu thập logs từ: AWS CloudTrail, CloudWatch, VPC Flow Logs; OpenStack (Keystone, Nova, Neutron logs); Azure Activity Logs; host syslog; container logs; network devices.  
- Chuẩn hoá, enrich và lưu trữ logs với index/retention policies.  
- Viết detection rules (Sigma / Elasticsearch watchers / Splunk searches) để phát hiện: brute-force, privilege escalation, lateral movement, data exfiltration, abnormal API activity.  
- Tích hợp Threat Intelligence feeds (STIX/TAXII, MISP) để enrich alerts.  
- Thiết kế playbooks (SOAR-lite) cho response automation (isolate host, revoke keys, create ticket).  
- Đánh giá theo metrics: detection accuracy, latency, throughput, storage cost, MTTR, analyst workload.

---

### 3. Kiến trúc & Công nghệ sử dụng (Architecture & Tech Stack)

**Choice A — Open Source ELK / OpenSearch stack (recommended for labs):**  

- Collectors/Agents: Filebeat / Metricbeat / Packetbeat / Winlogbeat / Fluent Bit.  
- Message bus (optional): Kafka for buffering/decoupling.  
- Ingest processors: Logstash / Fluentd or Kafka Streams for enrichment.  
- Datastore & search: Elasticsearch / OpenSearch cluster (with ILM indices).  
- Visualization & detection: Kibana / OpenSearch Dashboards, Alerting/Watcher.  
- Threat intel & enrichment: MISP, STIX/TAXII integration, GeoIP.  
- SOAR-lite: ElastAlert / ElastAlert2, custom playbooks (Python).

**Choice B — Splunk Enterprise / Splunk Cloud (if available):**  

- Forwarders: universal forwarder / heavy forwarder / HEC (HTTP Event Collector).  
- Indexers & Search Heads; Splunk ES for detection content, Splunk SOAR (Phantom) for playbooks.  
- Built‑in threat intelligence integration and prebuilt correlation searches (useful but license‑dependent).

**Supporting tools:**  

- Sigma for rule authoring (translate to Elasticsearch/Splunk).  
- OSQuery / Fleet for endpoint telemetry.  
- Velociraptor / Sysmon (for Windows-like telemetry) where applicable.  
- Jupyter / ELK notebooks for threat hunting queries.  

---

### 4. Threat Model & Detection Use Cases (Examples)

- **T1 — Credential brute-force / login storm:** many failed logins to console/API from single IP or distributed IPs.  
- **T2 — Compromised access key / token misuse:** unusual API calls (CreateUser, AttachPolicy, AssumeRole) from service account or new region.  
- **T3 — Lateral movement:** sequence of internal access patterns (VMA -> SMB -> RDP/SSH to VM B).  
- **T4 — Data exfiltration:** large GET/Download from object storage to suspicious external IP.  
- **T5 — Anomalous configuration changes:** sudden removal of CloudTrail, disabling logging, modifications to security groups.  
- **T6 — Supply-chain / CI compromise:** CI runner creates resources or deploys code with new credentials.  

---

### 5. Data Sources & Normalization (Schema)

**Primary sources:**  

- Cloud logs: AWS CloudTrail, CloudWatch Logs, VPC Flow Logs, S3 access logs; Azure Activity Logs; OpenStack audit logs (Keystone, Nova).  
- Host logs: syslog, auth.log, application logs.  
- Container logs: stdout/stderr via Fluentd/Fluent Bit.  
- Network telemetry: VPC Flow, Netflow (if available), IDS alerts.  
- Endpoint telemetry: osquery, Sysmon (Windows), process events.  
- Scanner outputs & threat intel feeds (MISP, AlienVault OTX).

**Canonical event schema (suggested):**  

```
{ "event_id", "timestamp", "source", "provider", "account", "region", "resource", "actor", "event_type", "action", "result", "src_ip", "dst_ip", "user_agent", "geo", "raw", "normalized_fields": {...} }
```

**Normalization steps:** flatten JSON, map provider-specific keys to canonical fields, enrich (geoip, asn, asset_owner, env), compute risk_score, fingerprint for de‑duplication.

---

### 6. Ingest Pipeline & Reliability (Design)

1. **Collection:** Beats/forwarders on sources → ship to Logstash/Fluentd or Kafka.  
2. **Buffering / Queueing:** Kafka or Redis to protect against spikes.  
3. **Ingest processing:** parsers, grok, JSON parsing, geoip, user mapping, threat intel join.  
4. **Indexing & ILM:** write to ES/OpenSearch indices with ILM policies for retention & rollover.  
5. **Alerting & SOAR:** detection engines trigger alerts → push to ticketing/Slack/Phantom.  
6. **Archival & cold storage:** archive raw logs to S3 (or object store) for forensics.  
7. **Monitoring & Observability:** monitor SIEM health (queue lag, ES cluster health, index size), use Prometheus + Grafana for infra metrics.

**Resilience features:** backpressure handling, dead-letter queues, retries, idempotent ingestion via event IDs.

---

### 7. Detection Rules & Content (Rule design & examples)

- Convert Sigma rules to target format (Elasticsearch DSL or Splunk SPL). Use community Sigma repo as base.  
- Example detections (high-level):  
  - **Failed login burst:** `failed_login_count > threshold within window` → alert.  
  - **Privilege escalation pattern:** sequence: `AttachRolePolicy` or `PutUserPolicy` followed by `CreateAccessKey` actions.  
  - **Suspicious data transfer:** `GET` large object size to IP outside ASN whitelist.  
  - **CloudTrail disabling:** `StopLogging` or `DeleteTrail` events → immediate HIGH severity alert.  
  - **Unusual region usage:** access from region not normally used by the account.  

**Rule tuning:** use whitelists, asset criticality, historical baselines, and suppressions to lower FP. Track rule performance metrics (TP/FP).

---

### 8. Threat Hunting & Analytics (Hunting playbook)

- Build hunting queries for TTPs (MITRE ATT&CK mapping): initial access, persistence, privilege escalation, defense evasion, exfiltration.  
- Example hunts: find sequences `assume-role -> create-key -> s3:getobject` within 24h.  
- Use interactive notebooks for pivoting: user → IP → resource → timeline.  
- Maintain hunting index for suspected events and enrich with timeline visualization.

---

### 9. ML / Anomaly Detection Approaches (Optional Advanced)

- **Unsupervised:** IsolationForest, OneClassSVM, Autoencoders on feature vectors (event frequency, unique resources, command sequences).  
- **Sequence models:** LSTM/Transformer to model user/API call sequences for session-level anomaly detection.  
- **Graph-based:** construct user ↔ resource graph; detect abnormal edge additions or sudden centrality changes using community detection or GNN.  
- **Hybrid:** combine rule-based alerts with ML score; require both to escalate to reduce FP.  
- **Model lifecycle:** offline training on historical logs, evaluation, drift detection, periodic retrain; explainability (SHAP) for analyst trust.

---

### 10. SOAR / Response Playbooks (Automation)

- **Containment playbook examples:**  
  - Revoke compromised access key (Cloud provider API).  
  - Isolate VM: modify security groups / apply network ACL to cut egress.  
  - Quarantine container/pod: cordon node / evict pod and rotate secrets.  
  - Enforce password rotations / invalidate sessions (Keycloak revoke).  
- **Automation tools:** custom Python scripts, Cloud Custodian actions, Azure Logic Apps, AWS Lambda, or Splunk SOAR.  
- **Human-in-loop strategy:** critical actions require manual approval; medium/low can be auto‑remediated per policy. Ensure “undo” runbook exists.

---

### 11. Forensics & Incident Investigation (Data retention & playbooks)

- Define retention policy for hot (searchable) vs cold (archived) logs based on compliance.  
- Preserve forensic evidence: immutable copies, integrity checksums, chain-of-custody notes.  
- Build investigation playbooks: timeline reconstruction, artifact collection (snapshots, memory dumps), root cause analysis.  
- Integrate with case management: create incident record, attach evidence, track triage & remediation.

---

### 12. Evaluation & Metrics (KPIs)

- **Detection metrics:** Precision, Recall, F1 for labeled test incidents (use synthetic attack scenarios).  
- **Operational metrics:** ingestion throughput (events/sec), indexing latency (median/p95), storage cost ($/month), query latency.  
- **Response metrics:** Mean Time To Detect (MTTD), Mean Time To Remediate (MTTR), analyst alerts/day, false positives/day.  
- **System health:** ES cluster CPU/memory, queue lag, disk utilization, index count.  
- **Threat hunting effectiveness:** # hunts -> findings validated as incidents.

---

### 13. Test Plan & Validation (Attack simulation)

- Create red-team simulation scripts (or use Atomic Red Team) to generate reproducible attack events: brute-force, key misuse, lateral movement, exfiltration.  
- Validate pipeline: ensure events ingested, correlated, and alerts generated.  
- Measure detection efficacy across scenarios with ground-truth labels.  
- Perform load testing: simulate sustained 1000 EPS (or target) and measure backpressure and latency.  
- Perform false-positive analysis with benign traffic to tune rules.

---

### 14. Deployment & Operations (Runbook)

- **Deployment:** Helm charts for ELK/OpenSearch stack; Beats & Fluent Bit for collection; Kafka cluster if used.  
- **CI/CD for SIEM content:** store rules & dashboards in Git; CI job to test rule syntax & deploy to SIEM.  
- **Day‑to‑day ops:** alerts triage rota, rule maintenance, index rollover policy, archive jobs, user access management.  
- **Backup & recovery:** snapshot ES indices regularly; test restore.  
- **Cost control:** monitor index growth, set ILM to move to warm/cold storage.

---

### 15. Rubric đánh giá (Suggested Grading Rubric)

- **Environment & ingestion (20%)**: collects logs from OpenStack & at least one cloud provider; normalization works.  
- **Detection content (25%)**: implemented a set of detection rules (covering at least 5 TTPs); demonstration of alerts.  
- **Threat intel & enrichment (10%)**: integrated at least one TI feed & used for enrichment.  
- **Response automation (20%)**: at least 2 playbooks implemented and demoed (revoke key, isolate host).  
- **Evaluation & tests (15%)**: attack simulation results, metrics, load testing.  
- **Documentation & deliverables (10%)**: runbooks, dashboards, code repo, demo video.

---

### 16. Milestones & Timeline (14 tuần đề xuất)

- Tuần 1–2: Research SIEM architectures & requirements; prepare lab OpenStack + AWS/Azure sample environments.  
- Tuần 3–4: Deploy ELK/OpenSearch or Splunk; install beats/forwarders.  
- Tuần 5: Implement normalization & enrichment pipeline (geoip, asn, owner).  
- Tuần 6–7: Develop detection rules (Sigma -> ES/Splunk) and test on historical logs.  
- Tuần 8: Integrate Threat Intel (MISP/TAXII) and enrich events.  
- Tuần 9: Implement SOAR-lite playbooks & automate 2 remediation actions.  
- Tuần 10: Run attack simulations and measure detection.  
- Tuần 11: Load testing & tuning.  
- Tuần 12: Forensics playbooks & evidence preservation.  
- Tuần 13: Final evaluation, metrics collection, UI dashboards.  
- Tuần 14: Finalize report, demo, presentation.

---

### 17. Deliverables (nộp cuối)

- Git repo: deployment scripts (Helm/Ansible), collector configs, parsing rules, Sigma rules, playbook scripts.  
- Dashboards and alert rules export (Kibana objects or Splunk content export).  
- Attack simulation scripts & ground-truth labels.  
- Runbooks for responders & system operators.  
- Test results: detection metrics, load test reports.  
- Demo video (5–10 phút), Technical report (15–30 trang), Slides (10–15 slides).

---

### 18. Ethical & Legal Considerations

- Only run attack simulations in lab/sandbox accounts. Do not generate traffic that affects third parties.  
- Avoid storing PII in shared demo artifacts; mask/anonymize logs.  
- Ensure privileged credentials for SIEM are securely stored (Vault) and rotated.  
- Disclosure: state limitations of lab setup in report.

---

### 19. Extensions & Advanced Ideas (Optional)

- Integrate with machine-readable ATT&CK mappings and produce MITRE ATT&CK heatmap dashboards.  
- Implement user behavior analytics (UBA) for insider threat detection.  
- Integrate Network Detection and Response (NDR) telemetry and enrich with packet-level context.  
- Build ML ops pipeline to manage model lifecycle for anomaly detectors.  
- Multi-tenant SIEM with tenant isolation for managed services.

---

### 20. Appendix: Example commands & snippets

**Install and run Filebeat:**  

```bash
filebeat modules enable aws
filebeat setup -e
filebeat -e
```

**Example Sigma rule conversion:**  

```bash
# convert sigma to es-dsl (using sigmatools)
sigmac -t es-qs rules/suspicious_logins.yml > suspicious_logins.json
```

**Test ingest with curl:**  

```bash
curl -XPOST "http://elasticsearch:9200/logs/_doc" -H 'Content-Type: application/json' -d '{"event":"test","timestamp":"2025-09-01T12:00:00Z"}'
```

**Revoke AWS access key (example remediation script snippet):**  

```python
import boto3
iam = boto3.client('iam')
iam.update_access_key(UserName='alice', AccessKeyId='AKIA...', Status='Inactive')
```
