# Version 2 – LangGraph / Multi-agent (+ CDK synth node)

V2 uses a LangGraph StateGraph:

- collect: reads repo and runs the rule engine
- synth: runs `npx cdk synth` and summarizes CloudFormation templates in `cdk.out/`
- Six pillar reviewers in parallel: Operational Excellence (observability), Security, Reliability, Performance Efficiency, Cost Optimization, Sustainability. Each considers static findings and synth summary.
- merge: lead reviewer merges into one section (AWS Well-Architected 6 pillars).
- report: generates final report.

## Prerequisites for synth
- **TypeScript CDK**: Node/CDK deps installed (`npm i` / `pnpm i` / `yarn`); `npx cdk synth` runs in repo.
- **Python CDK**: Same CLI (`npx cdk synth`); app entry is detected from `cdk.json` or `app.py` / `main.py` / `cdk_app.py` and passed as `--app "python app.py"`.
- If synth fails, analysis continues (graceful fallback).

## Extending
- Add more template-based rules (high signal):
  - KMS keys + policies
  - S3 server access logs
  - CloudTrail, VPC endpoints
- Add RAG: index Well-Architected + custom conventions and let agents cite

## Template-based rules included now
- S3 PublicAccessBlock (High)
- S3 Encryption (Medium)
- S3 Versioning (Low)
- RDS StorageEncrypted (High)
- RDS BackupRetentionPeriod (Medium)
- RDS MultiAZ (Medium, DBInstance)
- ALB access logs enabled (Low)
