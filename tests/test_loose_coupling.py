"""REL 4: functions do not call each other synchronously (CF-LAM-009, REL-033), and queue
and stream workers are idempotent (REPO-015)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import IdempotencyMissing
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _scan(root: Path, files: dict[str, str]) -> tuple[list, list[str]]:
    # Under prod/: the pytest directory name says "test", which reads as a dev stack.
    for rel, text in files.items():
        _write(root / "prod" / rel, text)
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings, ctx.rules_run


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def _fn(role: str | None = "CallerRole") -> dict:
    props: dict = {"Handler": "index.handler", "Runtime": "python3.12",
                   "Code": {"ZipFile": "def handler(e, c): pass"}}
    props["Role"] = ({"Fn::GetAtt": [role, "Arn"]} if role
                     else "arn:aws:iam::111122223333:role/r")
    return {"Type": "AWS::Lambda::Function", "Properties": props}


def _invoke_statement(resource: object, action: object = "lambda:InvokeFunction") -> dict:
    return {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}]}


def _role(policies: list | None = None) -> dict:
    props: dict = {"AssumeRolePolicyDocument": {"Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole",
        "Principal": {"Service": "lambda.amazonaws.com"}}]}}
    if policies:
        props["Policies"] = policies
    return {"Type": "AWS::IAM::Role", "Properties": props}


_WORKER_ARN = {"Fn::GetAtt": ["Worker", "Arn"]}
_INLINE = {"CallerRole": _role([{"PolicyName": "invoke",
                                 "PolicyDocument": _invoke_statement(_WORKER_ARN)}]),
           "Caller": _fn(), "Worker": _fn(None)}
_SEPARATE = {
    "CallerRole": _role(), "Caller": _fn(), "Worker": _fn(None),
    "Invoke": {"Type": "AWS::IAM::Policy", "Properties": {
        "PolicyName": "invoke", "Roles": [{"Ref": "CallerRole"}],
        "PolicyDocument": _invoke_statement(
            [_WORKER_ARN, {"Fn::Join": ["", [_WORKER_ARN, ":*"]]}], ["lambda:Invoke*"])}},
}

_TF_ROLE = '''
resource "aws_iam_role" "caller" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole",
                   Principal = { Service = "lambda.amazonaws.com" } }]
  })
}
resource "aws_iam_role" "worker" {
  assume_role_policy = aws_iam_role.caller.assume_role_policy
}
resource "aws_lambda_function" "caller" {
  function_name = "caller"
  role          = aws_iam_role.caller.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  filename      = "app.zip"
}
resource "aws_lambda_function" "worker" {
  function_name = "worker"
  role          = aws_iam_role.worker.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  filename      = "app.zip"
}
'''
_TF_ROLE_POLICY = '''
resource "aws_iam_role_policy" "invoke" {
  role   = aws_iam_role.caller.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:InvokeFunction"],
                   Resource = aws_lambda_function.worker.arn }]
  })
}
'''
_TF_ATTACHED_POLICY = '''
data "aws_iam_policy_document" "invoke" {
  statement {
    actions   = ["lambda:*"]
    resources = [aws_lambda_function.worker.arn]
  }
}
resource "aws_iam_policy" "invoke" {
  policy = data.aws_iam_policy_document.invoke.json
}
resource "aws_iam_role_policy_attachment" "invoke" {
  role       = aws_iam_role.caller.name
  policy_arn = aws_iam_policy.invoke.arn
}
'''
_TF_ASYNC = '''
resource "aws_sqs_queue" "failed" {}
resource "aws_lambda_function_event_invoke_config" "worker" {
  function_name = aws_lambda_function.worker.function_name
  destination_config {
    on_failure {
      destination = aws_sqs_queue.failed.arn
    }
  }
}
'''


def test_rules_answer_rel4() -> None:
    assert RULE_BEST_PRACTICES["CF-LAM-009"] == ("REL04-BP02",)
    assert RULE_BEST_PRACTICES["REL-033"] == ("REL04-BP02",)
    assert RULE_BEST_PRACTICES["REPO-015"] == ("REL04-BP04",)
    assert {"REL04-BP01", "REL04-BP02", "REL04-BP03", "REL04-BP04"}.isdisjoint(NOT_CHECKED)


# --- CF-LAM-009: a function's role may invoke another function of the stack ---

@pytest.mark.parametrize(
    "files",
    [
        {"t.json": _cfn(_INLINE)},
        {"t.json": _cfn(_SEPARATE)},
        {"main.tf": _TF_ROLE + _TF_ROLE_POLICY},
        {"main.tf": _TF_ROLE + _TF_ATTACHED_POLICY},
    ],
    ids=["cfn-inline-policy", "cfn-iam-policy", "tf-role-policy", "tf-policy-attachment"],
)
def test_direct_lambda_chain_fails(tmp_path: Path, files: dict) -> None:
    findings, ran = _scan(tmp_path, files)
    (hit,) = _found(findings, "CF-LAM-009")
    assert hit.question == "REL 4"
    assert hit.severity == "Medium" and hit.category == "Reliability"
    assert "aller" in hit.evidence.split(":", 1)[0]  # the caller, Caller or ...caller
    assert "orker" in hit.evidence.split("lambda:InvokeFunction on ", 1)[1]
    # A chain with no queue and no idempotency: REL 4 is not met.
    answer = {a.question.id: a for a in well_architected.answers(findings, ran)}["REL 4"]
    assert not answer.met


_ASYNC_CFN = {**_INLINE, "Failed": {"Type": "AWS::SQS::Queue", "Properties": {}},
              "WorkerAsync": {"Type": "AWS::Lambda::EventInvokeConfig", "Properties": {
                  "FunctionName": {"Ref": "Worker"}, "Qualifier": "$LATEST",
                  "DestinationConfig": {"OnFailure": {
                      "Destination": {"Fn::GetAtt": ["Failed", "Arn"]}}}}}}
_SFN_CFN = {
    "SfnRole": {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": {"Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole",
            "Principal": {"Service": "states.amazonaws.com"}}]},
        "Policies": [{"PolicyName": "invoke",
                      "PolicyDocument": _invoke_statement(_WORKER_ARN)}]}},
    "Machine": {"Type": "AWS::StepFunctions::StateMachine", "Properties": {
        "RoleArn": {"Fn::GetAtt": ["SfnRole", "Arn"]}, "DefinitionString": "{}"}},
    "CallerRole": _role(), "Caller": _fn(), "Worker": _fn(None),
}
_OUTSIDE_CFN = {
    "CallerRole": _role([{"PolicyName": "invoke", "PolicyDocument": _invoke_statement(
        "arn:aws:lambda:eu-west-1:111122223333:function:elsewhere")}]),
    "Caller": _fn(), "Worker": _fn(None),
}


@pytest.mark.parametrize(
    "files",
    [
        {"t.json": _cfn(_ASYNC_CFN)},
        {"t.json": _cfn(_SFN_CFN)},
        {"t.json": _cfn(_OUTSIDE_CFN)},
        {"main.tf": _TF_ROLE + _TF_ROLE_POLICY + _TF_ASYNC},
        {"main.tf": _TF_ROLE},
    ],
    ids=["cfn-async-destination", "cfn-step-functions", "cfn-outside-function",
         "tf-async-destination", "tf-no-invoke"],
)
def test_queue_async_or_orchestration_passes(tmp_path: Path, files: dict) -> None:
    findings, _ran = _scan(tmp_path, files)
    assert not _found(findings, "CF-LAM-009")


# --- REPO-015: queue and stream workers with no idempotency ---

_CDK_SQS = (
    "const fn = new lambda.Function(this, 'Worker', {});\n"
    "fn.addEventSource(new SqsEventSource(queue));\n"
)
_CFN_ESM = _cfn({
    "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
    "Worker": _fn(None),
    "Mapping": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
        "FunctionName": {"Ref": "Worker"}, "EventSourceArn": {"Fn::GetAtt": ["Queue", "Arn"]}}},
})
_TF_ESM = '''
resource "aws_sqs_queue" "jobs" {}
resource "aws_lambda_event_source_mapping" "jobs" {
  event_source_arn = aws_sqs_queue.jobs.arn
  function_name    = "worker"
}
'''


@pytest.mark.parametrize(
    ("files", "kind"),
    [
        ({"lib/stack.ts": _CDK_SQS, "package.json": "{}"}, "CDK SqsEventSource"),
        ({"t.json": _CFN_ESM}, "AWS::Lambda::EventSourceMapping"),
        ({"main.tf": _TF_ESM}, "aws_lambda_event_source_mapping"),
    ],
    ids=["cdk", "cloudformation", "terraform"],
)
def test_worker_without_idempotency_fails(tmp_path: Path, files: dict, kind: str) -> None:
    findings, _ran = _scan(tmp_path, files)
    (hit,) = _found(findings, "REPO-015")
    assert hit.question == "REL 4"
    assert hit.severity == "Medium" and hit.category == "Reliability"
    assert kind in hit.evidence and "Powertools idempotency" in hit.evidence
    assert hit.evidence.endswith("found none")


@pytest.mark.parametrize(
    "control",
    [
        {"src/handler.py": "from aws_lambda_powertools.utilities.idempotency import "
                           "idempotent\n\n@idempotent(persistence_store=store)\ndef handler(e, c):"
                           "\n    pass\n"},
        {"src/handler.ts": "import { makeIdempotent } from '@aws-lambda-powertools/idempotency';\n"},
        {"src/Handler.java": "import software.amazon.lambda.powertools.idempotency.Idempotent;\n"},
        {"src/Function.cs": "using AWS.Lambda.Powertools.Idempotency;\n"},
        {"fifo.tf": 'resource "aws_sqs_queue" "q" {\n  fifo_queue = true\n'
                    '  content_based_deduplication = true\n}\n'},
        {"src/producer.py": "sqs.send_message(QueueUrl=u, MessageBody=b, "
                            "MessageGroupId='g', MessageDeduplicationId=key)\n"},
        {"src/handler.py": "table.put_item(Item=item, "
                           "ConditionExpression='attribute_not_exists(pk)')\n"},
    ],
    ids=["powertools-python", "powertools-ts", "powertools-java", "powertools-dotnet",
         "fifo-content-dedupe", "dedupe-id", "conditional-write"],
)
def test_worker_with_idempotency_passes(tmp_path: Path, control: dict) -> None:
    findings, _ran = _scan(tmp_path, {"main.tf": _TF_ESM, **control})
    assert not _found(findings, "REPO-015")


def test_no_event_source_does_not_fire(tmp_path: Path) -> None:
    findings, _ran = _scan(tmp_path, {"main.tf": _TF_ROLE})
    assert not _found(findings, "REPO-015")


def test_idempotency_in_tests_does_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", _TF_ESM)
    _write(tmp_path / "tests" / "test_handler.py", "from aws_lambda_powertools.utilities."
           "idempotency import idempotent\n")
    assert IdempotencyMissing().run(tmp_path)


def test_sam_polled_event_counts(tmp_path: Path) -> None:
    _write(tmp_path / "template.yaml", (
        "Transform: AWS::Serverless-2016-10-31\nResources:\n  Worker:\n"
        "    Type: AWS::Serverless::Function\n    Properties:\n      Events:\n"
        "        Jobs:\n          Type: SQS\n          Properties:\n"
        "            Queue: !GetAtt Queue.Arn\n"))
    (hit,) = IdempotencyMissing().run(tmp_path)
    assert "SAM SQS event (template.yaml)" in hit.evidence
