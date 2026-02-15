# CloudFormation template-based rules (V2)

When `cdk synth` succeeds, the agent analyzes templates in `cdk.out/*.template.json` and creates extra findings (higher signal than code heuristics alone).

## Rules (by resource)

- **S3**: CF-S3-001 (PublicAccessBlock), CF-S3-002 (encryption), CF-S3-003 (versioning), CF-S3-004 (server access logging)
- **RDS**: CF-RDS-001 (StorageEncrypted), CF-RDS-002 (BackupRetentionPeriod), CF-RDS-003 (MultiAZ), CF-RDS-004 (PubliclyAccessible), CF-RDS-005 (DeletionProtection)
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
- **EKS**: CF-EKS-001 (control plane logging not enabled)

## By pillar (AWS Well-Architected 6 pillars)

| Pillar | CF rule IDs |
|--------|-------------|
| Operational Excellence | CF-S3-004, CF-CT-001, CF-CT-002, CF-FL-001, CF-EKS-001 |
| Security | CF-S3-001, CF-S3-002, CF-RDS-001, CF-RDS-004, CF-CT-003, CF-KMS-001, CF-SG-001, CF-CW-002, CF-SQS-001, CF-DDB-002 |
| Reliability | CF-S3-003, CF-RDS-002, CF-RDS-003, CF-RDS-005, CF-LAM-001, CF-DDB-001, CF-SQS-002 |
| Performance Efficiency | CF-PERF-001 |
| Cost Optimization | CF-CW-001 |
| Sustainability | CF-SUST-001, CF-SUST-002 |
| Observability (reported under Operational Excellence) | CF-ALB-001, CF-LAM-002, CF-APIGW-001, CF-APIGW-002 |
| Best Practices | CF-VPC-001 |
