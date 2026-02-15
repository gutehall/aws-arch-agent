"""Registry of all static rules (ALL_RULES list) used by V1 and V2."""
from __future__ import annotations
from aws_arch_agent.rules.security import (
    IamWildcardAction, IamWildcardResource, OpenSshToWorld, OpenDbPortsToWorld,
    S3PublicAccessNotBlocked, S3EncryptionMissing, KmsKeyPolicyWildcard,
)
from aws_arch_agent.rules.reliability import RdsMultiAzMissing, BackupRetentionMissing, LambdaDlqMissing
from aws_arch_agent.rules.cost import LogRetentionNeverExpire, MissingAutoscalingHint
from aws_arch_agent.rules.best_practices import MissingStandardTags
from aws_arch_agent.rules.operational_excellence import CloudTrailMissing, VpcFlowLogsMissing, XRayTracingMissing
from aws_arch_agent.rules.performance_efficiency import GravitonNotUsed, CachingHint
from aws_arch_agent.rules.sustainability import SpotNotConsidered, RightSizingHint

ALL_RULES = [
    IamWildcardAction(),
    IamWildcardResource(),
    OpenSshToWorld(),
    OpenDbPortsToWorld(),
    S3PublicAccessNotBlocked(),
    S3EncryptionMissing(),
    KmsKeyPolicyWildcard(),
    RdsMultiAzMissing(),
    BackupRetentionMissing(),
    LambdaDlqMissing(),
    LogRetentionNeverExpire(),
    MissingAutoscalingHint(),
    MissingStandardTags(),
    CloudTrailMissing(),
    VpcFlowLogsMissing(),
    XRayTracingMissing(),
    GravitonNotUsed(),
    CachingHint(),
    SpotNotConsidered(),
    RightSizingHint(),
]
