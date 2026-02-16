from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class IamWildcardAction(Rule):
    id = "SEC-001"
    title = "IAM policy uses wildcard actions"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # TS: Action: "*" or ['*']; Python: "Action": "*" in policy dicts or add_to_principal_policy
        pattern = r'Action\s*:\s*\[?\s*["\']\*["\']' if language == "typescript" else r'["\']Action["\']\s*:\s*["\']\*["\']'
        hits = rg(repo_path, pattern, glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in hits:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Restrict IAM actions to the minimum required (least privilege). Avoid '*' where possible.",
            ))
        return out


class IamWildcardResource(Rule):
    id = "SEC-002"
    title = "IAM policy uses wildcard resources"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        pattern = r'Resources?\s*:\s*\[?\s*["\']\*["\']' if language == "typescript" else r'["\']Resource["\']\s*:\s*["\']\*["\']'
        hits = rg(repo_path, pattern, glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in hits:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Restrict IAM resources to specific ARNs. Avoid '*' for resources where possible.",
            ))
        return out


class OpenSshToWorld(Rule):
    id = "SEC-003"
    title = "Security Group allows SSH from 0.0.0.0/0"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # TS: port: 22 or 0.0.0.0/0; Python: same in ec2.Port or CidrIp
        hits = rg(repo_path, r'0\.0\.0\.0/0.*(22|ssh)|port\s*:\s*22|\.tcp\(22\)', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in hits:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Restrict SSH to bastion/VPN or specific IP ranges. Avoid 0.0.0.0/0.",
            ))
        return out


class OpenDbPortsToWorld(Rule):
    id = "SEC-004"
    title = "Security Group exposes common DB ports to 0.0.0.0/0"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        hits = rg(repo_path, r'0\.0\.0\.0/0.*(3306|5432)|port\s*:\s*(3306|5432)|\.tcp\((3306|5432)\)', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in hits:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Databases should not be exposed publicly. Restrict ingress to app-tier security groups or private subnets.",
            ))
        return out


class S3PublicAccessNotBlocked(Rule):
    id = "SEC-005"
    title = "S3 bucket may miss Block Public Access"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Heuristic: bucket declared but no blockPublicAccess config in same repo
        bucket_pat = r'new\s+s3\.Bucket\(' if language == "typescript" else r's3\.Bucket\('
        buckets = rg(repo_path, bucket_pat, glob=code_glob(language))
        bpa = rg(repo_path, r'block_public_access|blockPublicAccess\s*:\s*s3\.BlockPublicAccess', glob=code_glob(language))
        out: List[Finding] = []
        if buckets and not bpa:
            f, ln, txt = buckets[0]
            suggested = (
                'new s3.Bucket(this, "B", {\n  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,\n});'
                if language == "typescript"
                else 's3.Bucket(self, "B", block_public_access=s3.BlockPublicAccess.BLOCK_ALL)'
            )
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set 'blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL' for buckets that should not be public.",
                suggested_code=suggested,
            ))
        return out


class S3EncryptionMissing(Rule):
    id = "SEC-006"
    title = "S3 bucket may miss encryption setting"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        bucket_pat = r'new\s+s3\.Bucket\(' if language == "typescript" else r's3\.Bucket\('
        buckets = rg(repo_path, bucket_pat, glob=code_glob(language))
        enc = rg(repo_path, r'encryption\s*:\s*s3\.|BucketEncryption\.', glob=code_glob(language))
        out: List[Finding] = []
        if buckets and not enc:
            f, ln, txt = buckets[0]
            suggested = (
                'new s3.Bucket(this, "B", { encryption: s3.BucketEncryption.S3_MANAGED });'
                if language == "typescript"
                else 's3.Bucket(self, "B", encryption=s3.BucketEncryption.S3_MANAGED)'
            )
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable S3 encryption (e.g. S3_MANAGED or KMS) per security requirements.",
                suggested_code=suggested,
            ))
        return out


class KmsKeyPolicyWildcard(Rule):
    id = "SEC-007"
    title = "KMS key policy may use wildcard principal"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        kms = rg(repo_path, r"kms\.(Key|Alias)|aws_kms\.(Key|Alias)|KMS", glob=code_glob(language))
        # Principal: * or Principal: "*" in policy
        wildcard = rg(repo_path, r'Principal\s*:\s*["\']?\*["\']?|Principal\s*:\s*\{[^}]*\*', glob=code_glob(language))
        out: List[Finding] = []
        if kms and wildcard:
            f, ln, txt = wildcard[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Restrict KMS key policy to specific principals (IAM roles/users). Avoid Principal '*'.",
            ))
        return out


class DynamoDbEncryptionMissing(Rule):
    id = "SEC-008"
    title = "DynamoDB table may miss encryption"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ddb_pat = r'new\s+(dynamodb\.Table|Table)\(' if language == "typescript" else r'(dynamodb.Table|aws_dynamodb.Table)\('
        tables = rg(repo_path, ddb_pat, glob=code_glob(language))
        # Check for encryption configuration (AWS_MANAGED, CUSTOMER_MANAGED, etc.)
        enc = rg(repo_path, r'encryption\s*:\s*(TableEncryption\.|dynamodb\.TableEncryption\.)|(AWS_MANAGED|CUSTOMER_MANAGED)', glob=code_glob(language))
        out: List[Finding] = []
        if tables and not enc:
            f, ln, txt = tables[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption for DynamoDB tables. Use AWS_MANAGED (default) or CUSTOMER_MANAGED (KMS) per requirements. In CDK: encryption: dynamodb.TableEncryption.AWS_MANAGED",
            ))
        return out


class ApiGatewayAuthMissing(Rule):
    id = "SEC-009"
    title = "API Gateway missing authentication"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        api_pat = r'new\s+(apigateway\.(RestApi|HttpApi)|RestApi|HttpApi)\(' if language == "typescript" else r'(apigateway\.(RestApi|HttpApi)|RestApi|HttpApi)\('
        apis = rg(repo_path, api_pat, glob=code_glob(language))
        auth = rg(repo_path, r'authorizer|authorizationType|ApiKeyRequired|CognitoUserPoolsAuthorizer|LambdaAuthorizer', glob=code_glob(language))
        out: List[Finding] = []
        if apis and not auth:
            f, ln, txt = apis[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure API Gateway authentication (API keys, IAM, Cognito User Pools, or Lambda authorizer). In CDK: defaultAuthorizer or authorizationType",
            ))
        return out


class ApiGatewayTlsVersion(Rule):
    id = "SEC-010"
    title = "API Gateway may not enforce TLS 1.2+"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        api_pat = r'new\s+(apigateway\.(RestApi|HttpApi|DomainName)|RestApi|HttpApi|DomainName)\(' if language == "typescript" else r'(apigateway\.(RestApi|HttpApi|DomainName)|RestApi|HttpApi|DomainName)\('
        apis = rg(repo_path, api_pat, glob=code_glob(language))
        tls = rg(repo_path, r'securityPolicy.*TLS_1_2|minimumTlsVersion', glob=code_glob(language))
        out: List[Finding] = []
        if apis and not tls:
            f, ln, txt = apis[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enforce TLS 1.2+ for API Gateway custom domains. In CDK: securityPolicy: apigateway.SecurityPolicy.TLS_1_2",
            ))
        return out


class AlbHttpsRedirect(Rule):
    id = "SEC-011"
    title = "ALB/NLB not enforcing HTTPS redirect"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alb_pat = r'new\s+elbv2\.(ApplicationLoadBalancer|NetworkLoadBalancer)\(' if language == "typescript" else r'elbv2\.(ApplicationLoadBalancer|NetworkLoadBalancer)\('
        albs = rg(repo_path, alb_pat, glob=code_glob(language))
        redirect = rg(repo_path, r'addRedirect|HttpsRedirect|redirect.*https|Protocol\.HTTPS', glob=code_glob(language))
        out: List[Finding] = []
        if albs and not redirect:
            f, ln, txt = albs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure HTTP to HTTPS redirect on ALB listeners. In CDK: listener.addRedirectResponse() or use Protocol.HTTPS",
            ))
        return out


class AlbSslPolicy(Rule):
    id = "SEC-012"
    title = "ALB using insecure SSL/TLS policy"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alb_pat = r'new\s+elbv2\.ApplicationLoadBalancer\(' if language == "typescript" else r'elbv2\.ApplicationLoadBalancer\('
        albs = rg(repo_path, alb_pat, glob=code_glob(language))
        ssl = rg(repo_path, r'sslPolicy.*ELBSecurityPolicy-TLS|sslPolicy.*2016|sslPolicy.*FS', glob=code_glob(language))
        out: List[Finding] = []
        if albs and not ssl:
            f, ln, txt = albs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Use secure SSL/TLS policy (ELBSecurityPolicy-TLS-1-2-2017-01 or later). In CDK: sslPolicy: elbv2.SslPolicy.RECOMMENDED",
            ))
        return out


class SqsEncryptionMissing(Rule):
    id = "SEC-013"
    title = "SQS queue not encrypted"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sqs_pat = r'new\s+sqs\.Queue\(' if language == "typescript" else r'sqs\.Queue\('
        queues = rg(repo_path, sqs_pat, glob=code_glob(language))
        enc = rg(repo_path, r'encryption\s*:\s*sqs\.QueueEncryption|encryptionMasterKey', glob=code_glob(language))
        out: List[Finding] = []
        if queues and not enc:
            f, ln, txt = queues[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable SQS encryption (KMS or SQS managed). In CDK: encryption: sqs.QueueEncryption.KMS_MANAGED",
            ))
        return out


class SnsEncryptionMissing(Rule):
    id = "SEC-014"
    title = "SNS topic not encrypted"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sns_pat = r'new\s+sns\.Topic\(' if language == "typescript" else r'sns\.Topic\('
        topics = rg(repo_path, sns_pat, glob=code_glob(language))
        enc = rg(repo_path, r'masterKey\s*:|encryptionMasterKey', glob=code_glob(language))
        out: List[Finding] = []
        if topics and not enc:
            f, ln, txt = topics[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable SNS topic encryption with KMS. In CDK: masterKey: kms.Key",
            ))
        return out


class SecretsManagerRotation(Rule):
    id = "SEC-015"
    title = "Secrets Manager rotation not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        secret_pat = r'new\s+secretsmanager\.Secret\(' if language == "typescript" else r'secretsmanager\.Secret\('
        secrets = rg(repo_path, secret_pat, glob=code_glob(language))
        rotation = rg(repo_path, r'addRotationSchedule|rotationSchedule', glob=code_glob(language))
        out: List[Finding] = []
        if secrets and not rotation:
            f, ln, txt = secrets[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable automatic rotation for Secrets Manager secrets. In CDK: secret.addRotationSchedule()",
            ))
        return out


class HardcodedSecrets(Rule):
    id = "SEC-016"
    title = "Potential hardcoded credentials/secrets in code"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Look for common patterns of hardcoded secrets
        patterns = [
            r'password\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'api[_-]?key\s*[:=]\s*["\'][^"\']{16,}["\']',
            r'secret\s*[:=]\s*["\'][^"\']{16,}["\']',
            r'access[_-]?key\s*[:=]\s*["\']AKIA[0-9A-Z]{16}["\']',
        ]
        out: List[Finding] = []
        for pattern in patterns:
            hits = rg(repo_path, pattern, glob=code_glob(language), max_hits=3)
            for f, ln, txt in hits:
                # Skip test files and examples
                if 'test' in f.lower() or 'example' in f.lower() or 'sample' in f.lower():
                    continue
                out.append(Finding(
                    id=self.id,
                    title=self.title,
                    severity="High",
                    category=self.category,
                    file=f,
                    line=ln,
                    evidence=txt[:100] + "...",
                    recommendation="Never hardcode secrets. Use AWS Secrets Manager, Systems Manager Parameter Store, or environment variables.",
                ))
        return out[:5]  # Limit to 5 findings to avoid noise


class LambdaEnvSecrets(Rule):
    id = "SEC-017"
    title = "Lambda environment variables may contain secrets"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        env_secrets = rg(repo_path, r'environment\s*:\s*\{[^}]*(password|secret|key|token)[^}]*\}', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in env_secrets[:3]:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt[:100],
                recommendation="Avoid storing secrets in Lambda environment variables. Use Secrets Manager or Parameter Store with proper IAM permissions.",
            ))
        return out


class CloudFrontHttpsOnly(Rule):
    id = "SEC-018"
    title = "CloudFront not enforcing HTTPS"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cf_pat = r'new\s+cloudfront\.(Distribution|CloudFrontWebDistribution)\(' if language == "typescript" else r'cloudfront\.(Distribution|CloudFrontWebDistribution)\('
        distros = rg(repo_path, cf_pat, glob=code_glob(language))
        https = rg(repo_path, r'ViewerProtocolPolicy\.REDIRECT_TO_HTTPS|viewerProtocolPolicy.*https-only', glob=code_glob(language))
        out: List[Finding] = []
        if distros and not https:
            f, ln, txt = distros[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enforce HTTPS on CloudFront distributions. In CDK: viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS",
            ))
        return out


class CloudFrontLegacyTls(Rule):
    id = "SEC-019"
    title = "CloudFront using legacy SSL/TLS"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cf_pat = r'new\s+cloudfront\.(Distribution|CloudFrontWebDistribution)\(' if language == "typescript" else r'cloudfront\.(Distribution|CloudFrontWebDistribution)\('
        distros = rg(repo_path, cf_pat, glob=code_glob(language))
        tls = rg(repo_path, r'minimumProtocolVersion.*TLSv1\.2|SecurityPolicyProtocol\.TLS_V1_2', glob=code_glob(language))
        out: List[Finding] = []
        if distros and not tls:
            f, ln, txt = distros[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Use TLS 1.2+ for CloudFront custom SSL certificates. In CDK: minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021",
            ))
        return out


class EcsReadonlyRootFs(Rule):
    id = "SEC-020"
    title = "ECS task definition not using read-only root filesystem"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        task_pat = r'new\s+ecs\.TaskDefinition\(' if language == "typescript" else r'ecs\.TaskDefinition\('
        tasks = rg(repo_path, task_pat, glob=code_glob(language))
        readonly = rg(repo_path, r'readonlyRootFilesystem\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if tasks and not readonly:
            f, ln, txt = tasks[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Use read-only root filesystem for ECS containers when possible. In CDK: readonlyRootFilesystem: true",
            ))
        return out


class RdsSslConnection(Rule):
    id = "SEC-021"
    title = "RDS not enforcing SSL/TLS connections"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        dbs = rg(repo_path, rds_pat, glob=code_glob(language))
        ssl = rg(repo_path, r'require_ssl|rds\.force_ssl|parameterGroup.*require_ssl', glob=code_glob(language))
        out: List[Finding] = []
        if dbs and not ssl:
            f, ln, txt = dbs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enforce SSL/TLS connections to RDS. Create a parameter group with rds.force_ssl=1 (PostgreSQL) or require_secure_transport=ON (MySQL)",
            ))
        return out


class VpcEndpointsMissing(Rule):
    id = "SEC-022"
    title = "VPC endpoints missing (security & cost improvement)"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        vpc_pat = r'new\s+ec2\.Vpc\(' if language == "typescript" else r'ec2\.Vpc\('
        vpcs = rg(repo_path, vpc_pat, glob=code_glob(language))
        endpoints = rg(repo_path, r'InterfaceVpcEndpoint|GatewayVpcEndpoint|addGatewayEndpoint|addInterfaceEndpoint', glob=code_glob(language))
        out: List[Finding] = []
        if vpcs and not endpoints:
            f, ln, txt = vpcs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Add VPC endpoints for AWS services (S3, DynamoDB gateway; EC2, SQS, etc. interface) to reduce NAT costs and improve security",
            ))
        return out


class KmsKeyRotation(Rule):
    id = "SEC-023"
    title = "KMS key rotation not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        kms_pat = r'new\s+kms\.Key\(' if language == "typescript" else r'kms\.Key\('
        keys = rg(repo_path, kms_pat, glob=code_glob(language))
        rotation = rg(repo_path, r'enableKeyRotation\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if keys and not rotation:
            f, ln, txt = keys[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable automatic key rotation for KMS customer-managed keys. In CDK: enableKeyRotation: true",
            ))
        return out


class WafMissing(Rule):
    id = "SEC-024"
    title = "WAF not enabled on ALB/API Gateway/CloudFront"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        resources = rg(repo_path, r'ApplicationLoadBalancer|RestApi|CloudFrontWebDistribution', glob=code_glob(language))
        waf = rg(repo_path, r'CfnWebACL|wafv2\.CfnWebACL|WebAclAssociation', glob=code_glob(language))
        out: List[Finding] = []
        if resources and not waf:
            f, ln, txt = resources[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider AWS WAF for protection against common web exploits (OWASP Top 10, bot control, rate limiting)",
            ))
        return out


class ElastiCacheEncryption(Rule):
    id = "SEC-025"
    title = "ElastiCache not using encryption in-transit/at-rest"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cache_pat = r'new\s+elasticache\.(CfnCacheCluster|CfnReplicationGroup)\(' if language == "typescript" else r'elasticache\.(CfnCacheCluster|CfnReplicationGroup)\('
        caches = rg(repo_path, cache_pat, glob=code_glob(language))
        enc = rg(repo_path, r'atRestEncryptionEnabled|transitEncryptionEnabled', glob=code_glob(language))
        out: List[Finding] = []
        if caches and not enc:
            f, ln, txt = caches[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption at-rest and in-transit for ElastiCache. Set atRestEncryptionEnabled and transitEncryptionEnabled to true",
            ))
        return out


class SecurityHubNotEnabled(Rule):
    id = "SEC-026"
    title = "Security Hub not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        securityhub = rg(repo_path, r'CfnHub|securityhub\.CfnHub', glob=code_glob(language))
        if not securityhub:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enabling AWS Security Hub for centralized security and compliance monitoring",
            )]
        return []


class GuardDutyNotEnabled(Rule):
    id = "SEC-027"
    title = "GuardDuty not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        guardduty = rg(repo_path, r'CfnDetector|guardduty\.CfnDetector', glob=code_glob(language))
        if not guardduty:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enabling Amazon GuardDuty for intelligent threat detection",
            )]
        return []


class EcrImageScanning(Rule):
    id = "SEC-028"
    title = "ECR repository image scanning not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ecr_pat = r'new\s+ecr\.Repository\(' if language == "typescript" else r'ecr\.Repository\('
        repos = rg(repo_path, ecr_pat, glob=code_glob(language))
        scanning = rg(repo_path, r'imageScanOnPush\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if repos and not scanning:
            f, ln, txt = repos[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable image scanning on push for ECR repositories to detect vulnerabilities. In CDK: imageScanOnPush: true",
            ))
        return out


class EcrImageImmutability(Rule):
    id = "SEC-029"
    title = "ECR image tag immutability not configured"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ecr_pat = r'new\s+ecr\.Repository\(' if language == "typescript" else r'ecr\.Repository\('
        repos = rg(repo_path, ecr_pat, glob=code_glob(language))
        immutable = rg(repo_path, r'imageTagMutability.*IMMUTABLE', glob=code_glob(language))
        out: List[Finding] = []
        if repos and not immutable:
            f, ln, txt = repos[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set image tag immutability for ECR repositories to prevent tag overwrites. In CDK: imageTagMutability: ecr.TagMutability.IMMUTABLE",
            ))
        return out


class EcrLifecyclePolicy(Rule):
    id = "SEC-030"
    title = "ECR repository lifecycle policy missing"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ecr_pat = r'new\s+ecr\.Repository\(' if language == "typescript" else r'ecr\.Repository\('
        repos = rg(repo_path, ecr_pat, glob=code_glob(language))
        lifecycle = rg(repo_path, r'addLifecycleRule|lifecyclePolicy', glob=code_glob(language))
        out: List[Finding] = []
        if repos and not lifecycle:
            f, ln, txt = repos[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Add lifecycle policy to ECR to automatically clean up old images and reduce storage costs. In CDK: repository.addLifecycleRule()",
            ))
        return out


class Route53HealthChecks(Rule):
    id = "SEC-031"
    title = "Route 53 health checks not configured"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        route53_pat = r'new\s+route53\.(HostedZone|RecordSet)\(' if language == "typescript" else r'route53\.(HostedZone|RecordSet)\('
        zones = rg(repo_path, route53_pat, glob=code_glob(language))
        health = rg(repo_path, r'HealthCheck|healthCheck', glob=code_glob(language))
        out: List[Finding] = []
        if zones and not health:
            f, ln, txt = zones[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure Route 53 health checks for failover and monitoring. In CDK: healthCheck property on records",
            ))
        return out


class Route53Dnssec(Rule):
    id = "SEC-032"
    title = "Route 53 DNSSEC not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        route53_pat = r'new\s+route53\.(PublicHostedZone|HostedZone)\(' if language == "typescript" else r'route53\.(PublicHostedZone|HostedZone)\('
        zones = rg(repo_path, route53_pat, glob=code_glob(language))
        dnssec = rg(repo_path, r'enableDnssec|dnssec', glob=code_glob(language))
        out: List[Finding] = []
        if zones and not dnssec:
            f, ln, txt = zones[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider enabling DNSSEC for Route 53 public hosted zones to protect against DNS spoofing",
            ))
        return out


class SsmParameterEncryption(Rule):
    id = "SEC-033"
    title = "SSM Parameter Store not using SecureString"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ssm_pat = r'new\s+ssm\.(StringParameter|CfnParameter)\(' if language == "typescript" else r'ssm\.(StringParameter|CfnParameter)\('
        params = rg(repo_path, ssm_pat, glob=code_glob(language))
        secure = rg(repo_path, r'ParameterType\.SECURE_STRING|type.*SecureString', glob=code_glob(language))
        out: List[Finding] = []
        if params and not secure:
            f, ln, txt = params[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Use SecureString type for sensitive SSM parameters. In CDK: type: ssm.ParameterType.SECURE_STRING",
            ))
        return out


class CognitoMfaMissing(Rule):
    id = "SEC-034"
    title = "Cognito User Pool MFA not required"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cognito_pat = r'new\s+cognito\.UserPool\(' if language == "typescript" else r'cognito\.UserPool\('
        pools = rg(repo_path, cognito_pat, glob=code_glob(language))
        mfa = rg(repo_path, r'mfa\s*:\s*cognito\.Mfa\.REQUIRED|mfa.*REQUIRED', glob=code_glob(language))
        out: List[Finding] = []
        if pools and not mfa:
            f, ln, txt = pools[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Require MFA for Cognito User Pools to enhance security. In CDK: mfa: cognito.Mfa.REQUIRED",
            ))
        return out


class CognitoPasswordPolicy(Rule):
    id = "SEC-035"
    title = "Cognito User Pool password policy may be weak"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cognito_pat = r'new\s+cognito\.UserPool\(' if language == "typescript" else r'cognito\.UserPool\('
        pools = rg(repo_path, cognito_pat, glob=code_glob(language))
        policy = rg(repo_path, r'passwordPolicy\s*:|minLength.*12|requireUppercase.*true', glob=code_glob(language))
        out: List[Finding] = []
        if pools and not policy:
            f, ln, txt = pools[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure strong password policy for Cognito (min 12 chars, require uppercase, lowercase, numbers, symbols). In CDK: passwordPolicy property",
            ))
        return out


class CognitoAdvancedSecurity(Rule):
    id = "SEC-036"
    title = "Cognito advanced security features not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cognito_pat = r'new\s+cognito\.UserPool\(' if language == "typescript" else r'cognito\.UserPool\('
        pools = rg(repo_path, cognito_pat, glob=code_glob(language))
        advanced = rg(repo_path, r'advancedSecurityMode.*ENFORCED|userPoolAddOns', glob=code_glob(language))
        out: List[Finding] = []
        if pools and not advanced:
            f, ln, txt = pools[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable advanced security features for Cognito (adaptive authentication, compromised credentials check). In CDK: advancedSecurityMode: cognito.AdvancedSecurityMode.ENFORCED",
            ))
        return out


class EfsEncryptionMissing(Rule):
    id = "SEC-037"
    title = "EFS encryption not enabled"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        efs_pat = r'new\s+efs\.FileSystem\(' if language == "typescript" else r'efs\.FileSystem\('
        filesystems = rg(repo_path, efs_pat, glob=code_glob(language))
        encryption = rg(repo_path, r'encrypted\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if filesystems and not encryption:
            f, ln, txt = filesystems[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption at rest for EFS file systems. In CDK: encrypted: true",
            ))
        return out


class KinesisEncryption(Rule):
    id = "SEC-038"
    title = "Kinesis stream encryption not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        kinesis_pat = r'new\s+kinesis\.(Stream|CfnStream)\(' if language == "typescript" else r'kinesis\.(Stream|CfnStream)\('
        streams = rg(repo_path, kinesis_pat, glob=code_glob(language))
        encryption = rg(repo_path, r'encryption\s*:\s*StreamEncryption|encryptionType.*KMS', glob=code_glob(language))
        out: List[Finding] = []
        if streams and not encryption:
            f, ln, txt = streams[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable server-side encryption for Kinesis streams. In CDK: encryption: kinesis.StreamEncryption.KMS",
            ))
        return out


class OpenSearchEncryption(Rule):
    id = "SEC-039"
    title = "OpenSearch domain encryption not enabled"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        os_pat = r'new\s+opensearch\.(Domain|CfnDomain)\(' if language == "typescript" else r'opensearch\.(Domain|CfnDomain)\('
        domains = rg(repo_path, os_pat, glob=code_glob(language))
        encryption = rg(repo_path, r'encryptionAtRest.*enabled.*true|nodeToNodeEncryption.*true', glob=code_glob(language))
        out: List[Finding] = []
        if domains and not encryption:
            f, ln, txt = domains[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption at rest and node-to-node encryption for OpenSearch. In CDK: encryptionAtRest.enabled: true, nodeToNodeEncryption: true",
            ))
        return out


class OpenSearchFineGrainedAccess(Rule):
    id = "SEC-040"
    title = "OpenSearch fine-grained access control not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        os_pat = r'new\s+opensearch\.(Domain|CfnDomain)\(' if language == "typescript" else r'opensearch\.(Domain|CfnDomain)\('
        domains = rg(repo_path, os_pat, glob=code_glob(language))
        fgac = rg(repo_path, r'fineGrainedAccessControl.*enabled|masterUserOptions', glob=code_glob(language))
        out: List[Finding] = []
        if domains and not fgac:
            f, ln, txt = domains[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable fine-grained access control for OpenSearch for better security. In CDK: fineGrainedAccessControl.enabled: true",
            ))
        return out


class OpenSearchVpcOnly(Rule):
    id = "SEC-041"
    title = "OpenSearch domain not in VPC"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        os_pat = r'new\s+opensearch\.(Domain|CfnDomain)\(' if language == "typescript" else r'opensearch\.(Domain|CfnDomain)\('
        domains = rg(repo_path, os_pat, glob=code_glob(language))
        vpc = rg(repo_path, r'vpcSubnets|vpc\s*:', glob=code_glob(language))
        out: List[Finding] = []
        if domains and not vpc:
            f, ln, txt = domains[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Deploy OpenSearch domains within VPC for secure access. In CDK: vpc and vpcSubnets properties",
            ))
        return out


class AthenaEncryption(Rule):
    id = "SEC-042"
    title = "Athena query result encryption not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        athena_pat = r'new\s+athena\.(CfnWorkGroup|Workgroup)\(' if language == "typescript" else r'athena\.(CfnWorkGroup|Workgroup)\('
        workgroups = rg(repo_path, athena_pat, glob=code_glob(language))
        encryption = rg(repo_path, r'encryptionConfiguration|resultConfigurationUpdates.*encryption', glob=code_glob(language))
        out: List[Finding] = []
        if workgroups and not encryption:
            f, ln, txt = workgroups[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption for Athena query results. Configure encryptionConfiguration in workgroup settings",
            ))
        return out


class GlueEncryption(Rule):
    id = "SEC-043"
    title = "Glue job encryption not configured"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        glue_pat = r'new\s+glue\.(Job|CfnJob)\(' if language == "typescript" else r'glue\.(Job|CfnJob)\('
        jobs = rg(repo_path, glue_pat, glob=code_glob(language))
        encryption = rg(repo_path, r'securityConfiguration|encryptionConfiguration', glob=code_glob(language))
        out: List[Finding] = []
        if jobs and not encryption:
            f, ln, txt = jobs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure encryption for Glue jobs (CloudWatch logs, job bookmarks, S3). Create a security configuration and reference it",
            ))
        return out


class MskEncryption(Rule):
    id = "SEC-044"
    title = "MSK cluster encryption not configured"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        msk_pat = r'new\s+msk\.(Cluster|CfnCluster)\(' if language == "typescript" else r'msk\.(Cluster|CfnCluster)\('
        clusters = rg(repo_path, msk_pat, glob=code_glob(language))
        encryption = rg(repo_path, r'encryptionInTransit|clientBroker.*TLS', glob=code_glob(language))
        out: List[Finding] = []
        if clusters and not encryption:
            f, ln, txt = clusters[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption in transit for MSK cluster. Configure encryptionInTransit with clientBroker: TLS",
            ))
        return out


class MskAuthentication(Rule):
    id = "SEC-045"
    title = "MSK cluster client authentication not configured"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        msk_pat = r'new\s+msk\.(Cluster|CfnCluster)\(' if language == "typescript" else r'msk\.(Cluster|CfnCluster)\('
        clusters = rg(repo_path, msk_pat, glob=code_glob(language))
        auth = rg(repo_path, r'clientAuthentication|sasl|tls', glob=code_glob(language))
        out: List[Finding] = []
        if clusters and not auth:
            f, ln, txt = clusters[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure client authentication for MSK (SASL/SCRAM or mTLS). In CDK: clientAuthentication property",
            ))
        return out


class SagemakerNotebookVpc(Rule):
    id = "SEC-046"
    title = "SageMaker notebook instance not in VPC"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sm_pat = r'new\s+sagemaker\.(CfnNotebookInstance|NotebookInstance)\(' if language == "typescript" else r'sagemaker\.(CfnNotebookInstance|NotebookInstance)\('
        notebooks = rg(repo_path, sm_pat, glob=code_glob(language))
        vpc = rg(repo_path, r'subnetId|securityGroupIds', glob=code_glob(language))
        out: List[Finding] = []
        if notebooks and not vpc:
            f, ln, txt = notebooks[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Deploy SageMaker notebook instances in VPC for secure access. Configure subnetId and securityGroupIds",
            ))
        return out


class SagemakerEncryption(Rule):
    id = "SEC-047"
    title = "SageMaker encryption not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sm_pat = r'new\s+sagemaker\.' if language == "typescript" else r'sagemaker\.'
        resources = rg(repo_path, sm_pat, glob=code_glob(language))
        encryption = rg(repo_path, r'kmsKeyId|volumeKmsKeyId', glob=code_glob(language))
        out: List[Finding] = []
        if resources and not encryption:
            f, ln, txt = resources[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable KMS encryption for SageMaker resources (notebooks, training jobs, endpoints). Configure kmsKeyId",
            ))
        return out


class AppSyncLogging(Rule):
    id = "SEC-048"
    title = "AppSync API logging not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        appsync_pat = r'new\s+appsync\.(GraphqlApi|CfnGraphQLApi)\(' if language == "typescript" else r'appsync\.(GraphqlApi|CfnGraphQLApi)\('
        apis = rg(repo_path, appsync_pat, glob=code_glob(language))
        logging = rg(repo_path, r'logConfig|fieldLogLevel', glob=code_glob(language))
        out: List[Finding] = []
        if apis and not logging:
            f, ln, txt = apis[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable logging for AppSync APIs for audit and troubleshooting. In CDK: logConfig with fieldLogLevel",
            ))
        return out


class AppSyncWaf(Rule):
    id = "SEC-049"
    title = "AppSync API not protected by WAF"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        appsync_pat = r'new\s+appsync\.(GraphqlApi|CfnGraphQLApi)\(' if language == "typescript" else r'appsync\.(GraphqlApi|CfnGraphQLApi)\('
        apis = rg(repo_path, appsync_pat, glob=code_glob(language))
        waf = rg(repo_path, r'CfnWebACL|wafv2.*GraphQL', glob=code_glob(language))
        out: List[Finding] = []
        if apis and not waf:
            f, ln, txt = apis[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider AWS WAF for AppSync GraphQL APIs to protect against abuse and injection attacks",
            ))
        return out


class FsxEncryption(Rule):
    id = "SEC-050"
    title = "FSx file system encryption not enabled"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        fsx_pat = r'new\s+fsx\.(LustreFileSystem|WindowsFileSystem|OntapFileSystem)\(' if language == "typescript" else r'fsx\.(LustreFileSystem|WindowsFileSystem|OntapFileSystem)\('
        filesystems = rg(repo_path, fsx_pat, glob=code_glob(language))
        encryption = rg(repo_path, r'kmsKey|kmsKeyId', glob=code_glob(language))
        out: List[Finding] = []
        if filesystems and not encryption:
            f, ln, txt = filesystems[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption for FSx file systems with KMS. In CDK: kmsKey property",
            ))
        return out


class TransferFamilyLogging(Rule):
    id = "SEC-051"
    title = "Transfer Family server logging not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        transfer_pat = r'new\s+transfer\.(CfnServer|Server)\(' if language == "typescript" else r'transfer\.(CfnServer|Server)\('
        servers = rg(repo_path, transfer_pat, glob=code_glob(language))
        logging = rg(repo_path, r'loggingRole|LoggingRole', glob=code_glob(language))
        out: List[Finding] = []
        if servers and not logging:
            f, ln, txt = servers[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable logging for Transfer Family servers for audit trail. Configure loggingRole",
            ))
        return out


class CodePipelineEncryption(Rule):
    id = "SEC-052"
    title = "CodePipeline artifact encryption not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        pipeline_pat = r'new\s+codepipeline\.(Pipeline|CfnPipeline)\(' if language == "typescript" else r'codepipeline\.(Pipeline|CfnPipeline)\('
        pipelines = rg(repo_path, pipeline_pat, glob=code_glob(language))
        encryption = rg(repo_path, r'encryptionKey|artifactBucket.*encryption', glob=code_glob(language))
        out: List[Finding] = []
        if pipelines and not encryption:
            f, ln, txt = pipelines[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable KMS encryption for CodePipeline artifact bucket. In CDK: artifactBucket with encryption",
            ))
        return out


class CodeBuildPrivilegedMode(Rule):
    id = "SEC-053"
    title = "CodeBuild project using privileged mode"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        privileged = rg(repo_path, r'privileged\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in privileged[:2]:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Avoid privileged mode in CodeBuild unless required for Docker-in-Docker. It increases security risk.",
            ))
        return out


class SecurityGroupEgressOpen(Rule):
    id = "SEC-054"
    title = "Security Group egress too permissive (0.0.0.0/0)"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sg_pat = r'new\s+ec2\.SecurityGroup\(' if language == "typescript" else r'ec2\.SecurityGroup\('
        sgs = rg(repo_path, sg_pat, glob=code_glob(language))
        egress_all = rg(repo_path, r'allowAllOutbound\s*:\s*true|0\.0\.0\.0/0.*egress', glob=code_glob(language))
        out: List[Finding] = []
        if sgs and egress_all:
            f, ln, txt = egress_all[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider restricting egress rules to specific destinations for defense-in-depth. In CDK: allowAllOutbound: false",
            ))
        return out


class NaclMissing(Rule):
    id = "SEC-055"
    title = "Network ACLs not configured"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        vpc_pat = r'new\s+ec2\.Vpc\(' if language == "typescript" else r'ec2\.Vpc\('
        vpcs = rg(repo_path, vpc_pat, glob=code_glob(language))
        nacl = rg(repo_path, r'NetworkAcl|subnetConfiguration.*networkAcl', glob=code_glob(language))
        out: List[Finding] = []
        if vpcs and not nacl:
            f, ln, txt = vpcs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider Network ACLs as an additional layer of network security beyond Security Groups",
            ))
        return out


class StackTerminationProtection(Rule):
    id = "SEC-056"
    title = "Stack termination protection not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        stack_pat = r'class\s+\w+\s+extends\s+Stack|super\(scope.*Stack' if language == "typescript" else r'class.*Stack\)|Stack\(scope'
        stacks = rg(repo_path, stack_pat, glob=code_glob(language))
        protection = rg(repo_path, r'terminationProtection\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if stacks and not protection:
            f, ln, txt = stacks[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable termination protection for production stacks. In CDK Stack props: terminationProtection: true",
            ))
        return out


class LambdaFunctionUrlAuth(Rule):
    id = "SEC-057"
    title = "Lambda function URL without authentication"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        func_url_pat = (
            r'addFunctionUrl|FunctionUrl\(' if language == "typescript"
            else r'add_function_url|FunctionUrl\('
        )
        func_urls = rg(repo_path, func_url_pat, glob=code_glob(language))
        auth = rg(repo_path, r'authType.*AWS_IAM|auth_type.*AWS_IAM', glob=code_glob(language))
        out: List[Finding] = []
        if func_urls and not auth:
            f, ln, txt = func_urls[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure authentication for Lambda function URLs. Use authType: lambda.FunctionUrlAuthType.AWS_IAM or integrate with API Gateway for more control.",
            ))
        return out


class EcsTaskRunAsRoot(Rule):
    id = "SEC-058"
    title = "ECS task may run as root user"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        task_pat = r'new\s+ecs\.(TaskDefinition|FargateTaskDefinition|Ec2TaskDefinition)\(' if language == "typescript" else r'ecs\.(TaskDefinition|FargateTaskDefinition|Ec2TaskDefinition)\('
        tasks = rg(repo_path, task_pat, glob=code_glob(language))
        run_as_non_root = rg(repo_path, r'runAsNonRoot|run_as_non_root\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if tasks and not run_as_non_root:
            f, ln, txt = tasks[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Run ECS containers as non-root user. Set runAsNonRoot: true and specify user in container definition.",
            ))
        return out


class RedshiftEncryptionMissing(Rule):
    id = "SEC-059"
    title = "Redshift cluster encryption not enabled"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rs_pat = r'new\s+redshift\.(Cluster|CfnCluster)\(' if language == "typescript" else r'redshift\.(Cluster|CfnCluster)\('
        clusters = rg(repo_path, rs_pat, glob=code_glob(language))
        enc = rg(repo_path, r'encrypted\s*:\s*true|encryption.*KMS', glob=code_glob(language))
        out: List[Finding] = []
        if clusters and not enc:
            f, ln, txt = clusters[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption at rest for Redshift clusters. In CDK: encrypted: true with kmsKeyId for customer-managed keys.",
            ))
        return out


class DocumentDbEncryptionMissing(Rule):
    id = "SEC-060"
    title = "DocumentDB cluster encryption not enabled"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        docdb_pat = r'new\s+docdb\.(DatabaseCluster|CfnDBCluster)\(' if language == "typescript" else r'docdb\.(DatabaseCluster|CfnDBCluster)\('
        clusters = rg(repo_path, docdb_pat, glob=code_glob(language))
        enc = rg(repo_path, r'storageEncrypted\s*:\s*true|storage_encrypted\s*:\s*True', glob=code_glob(language))
        out: List[Finding] = []
        if clusters and not enc:
            f, ln, txt = clusters[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption at rest for DocumentDB clusters. In CDK: storageEncrypted: true",
            ))
        return out


class NeptuneEncryptionMissing(Rule):
    id = "SEC-061"
    title = "Neptune database encryption not enabled"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        neptune_pat = r'new\s+neptune\.(DatabaseCluster|CfnDBCluster)\(' if language == "typescript" else r'neptune\.(DatabaseCluster|CfnDBCluster)\('
        clusters = rg(repo_path, neptune_pat, glob=code_glob(language))
        enc = rg(repo_path, r'storageEncrypted\s*:\s*true|storage_encrypted\s*:\s*True', glob=code_glob(language))
        out: List[Finding] = []
        if clusters and not enc:
            f, ln, txt = clusters[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable encryption at rest for Neptune databases. In CDK: storageEncrypted: true",
            ))
        return out


class CloudWatchLogsKmsEncryption(Rule):
    id = "SEC-062"
    title = "CloudWatch Logs not encrypted with KMS"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        log_pat = r'new\s+logs\.(LogGroup|LogGroupBase)\(' if language == "typescript" else r'logs\.(LogGroup|LogGroupBase)\('
        log_groups = rg(repo_path, log_pat, glob=code_glob(language))
        kms = rg(repo_path, r'encryptionKey|encryption_key|kmsKey', glob=code_glob(language))
        out: List[Finding] = []
        if log_groups and not kms:
            f, ln, txt = log_groups[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Encrypt CloudWatch Logs with KMS for sensitive data. In CDK: encryptionKey: kms.Key",
            ))
        return out


class BackupVaultEncryption(Rule):
    id = "SEC-063"
    title = "Backup vault encryption not configured"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        vault_pat = r'new\s+backup\.(BackupVault|CfnBackupVault)\(' if language == "typescript" else r'backup\.(BackupVault|CfnBackupVault)\('
        vaults = rg(repo_path, vault_pat, glob=code_glob(language))
        enc = rg(repo_path, r'encryptionKeyArn|encryption_key_arn', glob=code_glob(language))
        out: List[Finding] = []
        if vaults and not enc:
            f, ln, txt = vaults[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure KMS encryption for Backup vaults. In CDK: encryptionKeyArn property",
            ))
        return out


class RdsPubliclyAccessible(Rule):
    id = "SEC-064"
    title = "RDS instance may be publicly accessible"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        dbs = rg(repo_path, rds_pat, glob=code_glob(language))
        public_false = rg(repo_path, r'publiclyAccessible\s*:\s*false|publicly_accessible\s*:\s*False', glob=code_glob(language))
        out: List[Finding] = []
        if dbs and not public_false:
            f, ln, txt = dbs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set publiclyAccessible: false for RDS instances. Databases should not be exposed to the internet.",
            ))
        return out


class MacieNotEnabled(Rule):
    id = "SEC-065"
    title = "Amazon Macie not enabled for sensitive data discovery"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        s3_buckets = rg(repo_path, r'new\s+s3\.Bucket\(' if language == "typescript" else r's3\.Bucket\(', glob=code_glob(language))
        macie = rg(repo_path, r'macie|Macie|CfnSession', glob=code_glob(language))
        out: List[Finding] = []
        if s3_buckets and not macie:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enabling Amazon Macie for automated discovery of sensitive data in S3 buckets.",
            )]
        return out
