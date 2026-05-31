from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg

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


