# CloudFormation template-based rules (V2)

CloudFormation template rules run in V2 when the agent has access to template files. They produce findings with higher signal than code heuristics alone.

**When CF rules run:**

- After **`cdk synth`** — templates in `cdk.out/*.template.json` are analyzed.
- With **`--templates`** — you provide a path to a directory or file; the agent discovers templates and skips synth. No Node.js or CDK required. Use this for raw CloudFormation repos.

**Template formats:** JSON (including `*.template.json`) and YAML (`*.yaml`, `*.yml`). With `--templates`, the agent discovers all of these under the given path.

## Rules (by resource)

- **S3**: CF-S3-001 (PublicAccessBlock), CF-S3-002 (encryption), CF-S3-003 (versioning), CF-S3-004 (server access logging)
- **RDS**: CF-RDS-001 (StorageEncrypted), CF-RDS-002 (BackupRetentionPeriod), CF-RDS-003 (MultiAZ), CF-RDS-004 (PubliclyAccessible), CF-RDS-005 (DeletionProtection), CF-PERF-003 (large instance right-sizing)
- **ALB**: CF-ALB-001 (access logs)
- **CloudTrail**: CF-CT-001 (log file validation), CF-CT-002 (multi-region), CF-CT-003 (KMS encryption)
- **KMS**: CF-KMS-001 (key policy wildcard principal)
- **VPC**: CF-VPC-001 (no VPC endpoints), CF-FL-001 (no flow logs)
- **Lambda**: CF-LAM-001 (no DLQ), CF-LAM-002 (X-Ray not enabled), CF-PERF-001 (ARM64 not used)
- **DynamoDB**: CF-DDB-001 (PITR not enabled), CF-DDB-002 (SSE not enabled)
- **Security groups**: CF-SG-001 (0.0.0.0/0 or ::/0 on sensitive ports)
- **CloudWatch Logs**: CF-CW-001 (no retention), CF-CW-002 (no KMS)
- **SQS**: CF-SQS-001 (encryption not configured), CF-SQS-002 (no redrive/DLQ)
- **API Gateway**: CF-APIGW-001 (access logging), CF-APIGW-002 (X-Ray tracing)
- **Auto Scaling**: CF-SUST-001 (no Spot / mixed instances)
- **ECS**: CF-SUST-002 (Fargate without FARGATE_SPOT)
- **EC2**: CF-PERF-004 (large instance right-sizing)
- **Launch Template**: CF-SUST-003 (no Spot when no ASG in template)
- **EKS**: CF-EKS-001 (control plane logging not enabled)
- **Template-level**: CF-PERF-002 (consider caching when API/Lambda, no CloudFront/ElastiCache), CF-COST-002 (NAT Gateway cost hint)

## By pillar (AWS Well-Architected 6 pillars)

| Pillar | CF rule IDs |
|--------|-------------|
| Operational Excellence | CF-S3-004, CF-CT-001, CF-CT-002, CF-FL-001, CF-EKS-001 |
| Security | CF-S3-001, CF-S3-002, CF-RDS-001, CF-RDS-004, CF-CT-003, CF-KMS-001, CF-SG-001, CF-CW-002, CF-SQS-001, CF-DDB-002 |
| Reliability | CF-S3-003, CF-RDS-002, CF-RDS-003, CF-RDS-005, CF-LAM-001, CF-DDB-001, CF-SQS-002 |
| Performance Efficiency | CF-PERF-001, CF-PERF-002, CF-PERF-003, CF-PERF-004 |
| Cost Optimization | CF-CW-001, CF-COST-002 |
| Sustainability | CF-SUST-001, CF-SUST-002, CF-SUST-003 |
| Observability (reported under Operational Excellence) | CF-ALB-001, CF-LAM-002, CF-APIGW-001, CF-APIGW-002 |
| Best Practices | CF-VPC-001 |

## See also

- [REFERENCE.md](REFERENCE.md) — CLI options and static (code) rule IDs (OPS-001, SEC-001, etc.).
- [CONFIG.md](CONFIG.md) — `templates` and `no_synth` config keys for V2.
