from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg

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


