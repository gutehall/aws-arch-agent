from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.rules.scope import findings_when_same_file
from aws_arch_agent.tools.rg import rg

# World-open peers. A private CIDR such as 10.0.0.0/16 is not a match.
_WORLD_OPEN = r"0\.0\.0\.0/0|::/0|Peer\.anyIpv4\(|Peer\.anyIpv6\(|Peer\.any_ipv4\(|Peer\.any_ipv6\("
_SSH_PORT = r"(?i)\b(?:from_?)?port\s*[:=]?\s*22\b|\.tcp\(\s*22\s*\)|Port\.SSH\b"
_DB_PORT = r"(?i)\b(?:from_?)?port\s*[:=]?\s*(?:3306|5432|27017)\b|\.tcp\(\s*(?:3306|5432|27017)\s*\)"

class OpenSshToWorld(Rule):
    id = "SEC-003"
    title = "Security Group allows SSH from 0.0.0.0/0"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        glob = code_glob(language)
        return findings_when_same_file(
            self,
            rg(repo_path, _WORLD_OPEN, glob=glob),
            rg(repo_path, _SSH_PORT, glob=glob),
            "Restrict SSH to bastion/VPN or specific IP ranges. Avoid 0.0.0.0/0.",
        )



class OpenDbPortsToWorld(Rule):
    id = "SEC-004"
    title = "Security Group exposes common DB ports to 0.0.0.0/0"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        glob = code_glob(language)
        return findings_when_same_file(
            self,
            rg(repo_path, _WORLD_OPEN, glob=glob),
            rg(repo_path, _DB_PORT, glob=glob),
            "Databases should not be exposed publicly. Restrict ingress to app-tier security groups or private subnets.",
        )



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



class SecurityGroupEgressOpen(Rule):
    id = "SEC-054"
    title = "Security Group egress too permissive (0.0.0.0/0)"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sg_pat = r'new\s+ec2\.SecurityGroup\(' if language == "typescript" else r'ec2\.SecurityGroup\('
        sgs = rg(repo_path, sg_pat, glob=code_glob(language))
        egress_all = rg(
            repo_path,
            r"allowAllOutbound\s*:\s*true|allow_all_outbound\s*=\s*True|0\.0\.0\.0/0.*egress",
            glob=code_glob(language),
        )
        return findings_when_same_file(
            self,
            sgs,
            egress_all,
            "Consider restricting egress rules to specific destinations for defense-in-depth. In CDK: allowAllOutbound: false",
        )



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


