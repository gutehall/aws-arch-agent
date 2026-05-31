from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg

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


