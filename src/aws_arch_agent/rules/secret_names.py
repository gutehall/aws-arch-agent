"""Names and values that look like secrets, shared by the template checks.

CF-PAR-001/002 read template parameters and Terraform variables, CF-LAM-005 Lambda
environment variables; CodeBuild and ECS environment checks reuse the same rules.
"""
from __future__ import annotations

import re
from typing import Any

# A parameter name that holds a secret (DbPassword, ApiKey, GithubToken, ...).
SECRET_NAME = re.compile(
    r"pass(?:word|wd|phrase|code)|pwd|secret|token(?!iz)|api_?key|private_?key|credential|"
    r"auth_?key|access_?key|signing_?key|shared_?key|client_?secret|connection_?string",
    re.IGNORECASE,
)
# Names that point at a secret or describe one, without holding it (DbSecretArn, KeyName,
# PasswordMinLength, TokenIssuer). A secret parameter named *Param still holds the value.
SECRET_REFERENCE = re.compile(
    r"(?:arn|name|id|length|policy|ttl|expiry|expiration|rotation|version|path|prefix|type|"
    r"enabled|count|url|uri|header|duration|days|audience|issuer|complexity|validity|format|"
    r"symbols|numbers|uppercase|lowercase|require\w*|tokens|limit|size)$",
    re.IGNORECASE,
)
# Counts and limits named after a secret word, such as MaxTokens or min_password_age.
# Case-sensitive, so the next word must start a new word: MinioSecretKey is a secret.
# An upper-case name needs the separator: MAX_TOKENS is a limit, MINIO_SECRET_KEY is not.
SECRET_LIMIT = re.compile(r"^(?:(?:max|Max|min|Min)(?:imum)?(?:_|[A-Z0-9])|(?:MAX|MIN)(?:IMUM)?_)")


def is_secret_name(name: str) -> bool:
    """True for a name that holds a secret (DbPassword, API_KEY), not one that points at
    or describes one (DbSecretArn, PasswordMinLength, MaxTokens)."""
    return (
        bool(SECRET_NAME.search(name))
        and not SECRET_REFERENCE.search(name)
        and not SECRET_LIMIT.match(name)
    )


_FLAGS = frozenset({"true", "false", "yes", "no", "on", "off", "none", "null", "enabled", "disabled"})
# Literal strings that are references, not the secret itself.
_REFERENCE_VALUE = re.compile(r"^(?:arn:|\{\{resolve:|\$\{|ssm:|secretsmanager:)", re.IGNORECASE)


def is_literal_secret(value: Any) -> bool:
    """True for a non-empty literal string that is not a reference (an ARN, a dynamic
    reference, an interpolation). An intrinsic or a Terraform expression is not literal."""
    if type(value) is not str:
        return False
    text = value.strip()
    if not text or _REFERENCE_VALUE.match(text) or text.lower() in _FLAGS:
        return False
    return not re.fullmatch(r"[\d.]+", text)  # a number is a setting (TOKEN_TTL_HOURS=12)
