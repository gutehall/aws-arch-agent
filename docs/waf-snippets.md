# Sample Well-Architected notes

Short reference for `--rag` and `rag.path`. Replace it with your own conventions. Retrieval is keyword overlap unless embeddings are turned on.

## Security

Block public access on S3. Do not put passwords or tokens in Lambda environment variables. Use Secrets Manager.

## Reliability

Give queues a dead-letter queue. Turn on RDS deletion protection and a backup retention period.

## Operational Excellence

Enable CloudTrail and VPC flow logs at the account, not in every app stack. Alarm on the DLQ depth.

## Performance Efficiency

Put CloudFront or an API cache in front of a public API. An S3 bucket or a queue does not need one.

## Cost Optimization

Set log retention. Prefer Graviton where the runtime supports it.

## Sustainability

Use Spot or Fargate Spot for interruptible workers.
