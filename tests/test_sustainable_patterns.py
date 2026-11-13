"""SUS 3: software and architecture patterns. Components with no use (REPO-103), compute at its
resource ceiling with no profile (REPO-104), end-user devices (REPO-105), and data access
patterns (REPO-106)."""
import json
from pathlib import Path

import pytest
from test_data_store_choice import EBS_VOLUME, INSTANCE
from test_demand_management import SOURCES, _stack, _write

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    DataAccessPatternMismatch,
    DeviceImpactUnaddressed,
    HotCodeUnprofiled,
    PurposeBuiltDataStoreMissing,
    UnusedComponents,
)

RULES = (UnusedComponents(), HotCodeUnprofiled(), DeviceImpactUnaddressed(),
         DataAccessPatternMismatch())


def _cf(kind: str, **props: object) -> dict:
    return {"Type": kind, "Properties": props}


# REPO-103: components with no use.

UNUSED = {
    "ECS service at 0": {
        "cdk": "new ecs.FargateService(this, 'Svc', { cluster, taskDefinition, desiredCount: 0 });\n",
        "cloudformation": {"Svc": _cf("AWS::ECS::Service", DesiredCount=0)},
        "terraform": 'resource "aws_ecs_service" "svc" {\n  desired_count = 0\n}\n',
    },
    "ASG max 0": {
        "cdk": "new autoscaling.AutoScalingGroup(this, 'Asg', { vpc, maxCapacity: 0 });\n",
        "cloudformation": {"Asg": _cf("AWS::AutoScaling::AutoScalingGroup", MaxSize="0",
                                      MinSize="0")},
        "terraform": 'resource "aws_autoscaling_group" "asg" {\n  max_size = 0\n}\n',
    },
    "Lambda reserved 0": {
        "cdk": "new lambda.Function(this, 'Fn', { runtime, handler, code, "
               "reservedConcurrentExecutions: 0 });\n",
        "cloudformation": {"Fn": _cf("AWS::Lambda::Function", ReservedConcurrentExecutions=0)},
        "terraform": 'resource "aws_lambda_function" "fn" {\n'
                     '  reserved_concurrent_executions = 0\n}\n',
    },
    "disabled rule": {
        "cdk": "new events.Rule(this, 'R', { enabled: false, targets: [t] });\n",
        "cloudformation": {"R": _cf("AWS::Events::Rule", State="DISABLED",
                                    Targets=[{"Arn": "x", "Id": "1"}])},
        "terraform": 'resource "aws_cloudwatch_event_rule" "r" {\n  is_enabled = false\n}\n'
                     'resource "aws_cloudwatch_event_target" "t" {\n'
                     '  rule = aws_cloudwatch_event_rule.r.name\n}\n',
    },
    "rule without targets": {
        "cdk": "const rule = new events.Rule(this, 'R', { schedule });\n",
        "cloudformation": {"R": _cf("AWS::Events::Rule", ScheduleExpression="rate(1 day)")},
        "terraform": 'resource "aws_cloudwatch_event_rule" "r" {\n'
                     '  schedule_expression = "rate(1 day)"\n}\n',
    },
    "topic without subscription": {
        "cdk": "const topic = new sns.Topic(this, 'T');\n",
        "cloudformation": {"T": _cf("AWS::SNS::Topic")},
        "terraform": 'resource "aws_sns_topic" "t" {\n  name = "t"\n}\n',
    },
    "untriggered function": {
        "cdk": "new lambda.Function(this, 'Fn', { runtime, handler, code });\n",
        "cloudformation": {"Fn": _cf("AWS::Lambda::Function", Runtime="python3.12")},
        "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n',
    },
}
IN_USE = {
    "ECS service at 0": {
        "cdk": "new ecs.FargateService(this, 'Svc', { cluster, taskDefinition, desiredCount: 2 });\n",
        "cloudformation": {"Svc": _cf("AWS::ECS::Service", DesiredCount=2)},
        "terraform": 'resource "aws_ecs_service" "svc" {\n  desired_count = 2\n}\n',
    },
    "ASG max 0": {
        "cdk": "new autoscaling.AutoScalingGroup(this, 'Asg', { vpc, maxCapacity: 4 });\n",
        "cloudformation": {"Asg": _cf("AWS::AutoScaling::AutoScalingGroup", MaxSize="4")},
        "terraform": 'resource "aws_autoscaling_group" "asg" {\n  max_size = 4\n}\n',
    },
    "Lambda reserved 0": {
        "cdk": "const fn = new lambda.Function(this, 'Fn', { runtime, handler, code, "
               "reservedConcurrentExecutions: 5 });\nfn.addEventSource(src);\n",
        "cloudformation": {"Fn": _cf("AWS::Lambda::Function", ReservedConcurrentExecutions=5),
                           "Perm": _cf("AWS::Lambda::Permission",
                                       FunctionName={"Ref": "Fn"})},
        "terraform": 'resource "aws_lambda_function" "fn" {\n'
                     '  reserved_concurrent_executions = 5\n}\n'
                     'resource "aws_lambda_permission" "p" {\n'
                     '  function_name = aws_lambda_function.fn.function_name\n}\n',
    },
    "disabled rule": {
        "cdk": "new events.Rule(this, 'R', { enabled: true, targets: [t] });\n",
        "cloudformation": {"R": _cf("AWS::Events::Rule", State="ENABLED",
                                    Targets=[{"Arn": "x", "Id": "1"}])},
        "terraform": 'resource "aws_cloudwatch_event_rule" "r" {\n  is_enabled = true\n}\n'
                     'resource "aws_cloudwatch_event_target" "t" {\n'
                     '  rule = aws_cloudwatch_event_rule.r.name\n}\n',
    },
    "rule without targets": {
        "cdk": "const rule = new events.Rule(this, 'R', { schedule });\n"
               "rule.addTarget(new targets.LambdaFunction(fn));\n",
        "cloudformation": {"R": _cf("AWS::Events::Rule", ScheduleExpression="rate(1 day)",
                                    Targets=[{"Arn": "x", "Id": "1"}])},
        "terraform": 'resource "aws_cloudwatch_event_rule" "r" {\n'
                     '  schedule_expression = "rate(1 day)"\n}\n'
                     'resource "aws_cloudwatch_event_target" "t" {\n'
                     '  rule = aws_cloudwatch_event_rule.r.name\n}\n',
    },
    "topic without subscription": {
        "cdk": "const topic = new sns.Topic(this, 'T');\n"
               "topic.addSubscription(new subs.EmailSubscription('a@b.c'));\n",
        "cloudformation": {"T": _cf("AWS::SNS::Topic"),
                           "S": _cf("AWS::SNS::Subscription", TopicArn={"Ref": "T"})},
        "terraform": 'resource "aws_sns_topic" "t" {\n  name = "t"\n}\n'
                     'resource "aws_sns_topic_subscription" "s" {\n'
                     '  topic_arn = aws_sns_topic.t.arn\n}\n',
    },
    "untriggered function": {
        "cdk": "const fn = new lambda.Function(this, 'Fn', { runtime, handler, code });\n"
               "new apigw.LambdaRestApi(this, 'Api', { handler: fn });\n",
        "cloudformation": {"Fn": _cf("AWS::Lambda::Function", Runtime="python3.12"),
                           "Url": _cf("AWS::Lambda::Url", TargetFunctionArn={"Fn::GetAtt":
                                                                            ["Fn", "Arn"]})},
        "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n'
                     'resource "aws_lambda_function_url" "u" {\n'
                     '  function_name = aws_lambda_function.fn.function_name\n}\n',
    },
}
SIGNALS = tuple(UNUSED)


@pytest.mark.parametrize("signal", SIGNALS)
@pytest.mark.parametrize("source", SOURCES)
def test_unused_component_fires_repo_103(tmp_path: Path, source: str, signal: str) -> None:
    _stack(tmp_path, source, UNUSED[signal][source])
    (hit,) = UnusedComponents().run(tmp_path)
    assert hit.id == "REPO-103"
    assert "prod/" in hit.evidence


@pytest.mark.parametrize("signal", SIGNALS)
@pytest.mark.parametrize("source", SOURCES)
def test_component_in_use_passes_repo_103(tmp_path: Path, source: str, signal: str) -> None:
    _stack(tmp_path, source, IN_USE[signal][source])
    assert UnusedComponents().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_evidence_names_the_component_and_file_repo_103(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, UNUSED["ECS service at 0"][source])
    (hit,) = UnusedComponents().run(tmp_path)
    assert "ECS service Svc" in hit.evidence or "ECS service svc" in hit.evidence
    assert "desired count 0" in hit.evidence


def test_function_named_in_another_file_passes_repo_103(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", UNUSED["untriggered function"]["cloudformation"])
    assert len(UnusedComponents().run(tmp_path)) == 1
    _write(tmp_path / "prod/other.template.json", json.dumps({"Resources": {
        "Perm": _cf("AWS::Lambda::Permission", FunctionName="Fn")}}))
    assert UnusedComponents().run(tmp_path) == []


def test_topic_referenced_elsewhere_passes_repo_103(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {
        "T": _cf("AWS::SNS::Topic"),
        "A": _cf("AWS::CloudWatch::Alarm", AlarmActions=[{"Ref": "T"}]),
    })
    assert UnusedComponents().run(tmp_path) == []


def test_repo_099_assets_are_not_repeated_repo_103(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n')
    assert UnusedComponents().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_is_skipped_repo_103(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", UNUSED["ECS service at 0"]["terraform"], env=env)
    assert UnusedComponents().run(tmp_path) == []


def test_python_cdk_repo_103(tmp_path: Path) -> None:
    _write(tmp_path / "prod/stack.py",
           "svc = ecs.FargateService(self, 'Svc', cluster=c, desired_count=0)\n"
           "NOTE = \"ecs.FargateService(self, 'X', desired_count=0)\"\n")
    (hit,) = UnusedComponents().run(tmp_path)
    assert "ECS service svc" in hit.evidence and "desired count 0" in hit.evidence
    _write(tmp_path / "prod/stack.py",
           "NOTE = \"ecs.FargateService(self, 'X', desired_count=0)\"\n"
           'DOC = """\nsvc = ecs.FargateService(self, "S", desired_count=0)\n"""\n')
    assert UnusedComponents().run(tmp_path) == []


# REPO-104: compute at its ceiling with no profile.

CEILING = {
    "Lambda 10240": {
        "cdk": "new lambda.Function(this, 'Big', { runtime, handler, code, memorySize: 10240 });\n",
        "cloudformation": {"Big": _cf("AWS::Lambda::Function", MemorySize=10240)},
        "terraform": 'resource "aws_lambda_function" "big" {\n  memory_size = 10240\n}\n',
    },
    "Lambda 900 s": {
        "cdk": "new lambda.Function(this, 'Big', { memorySize: 4096, "
               "timeout: Duration.seconds(900) });\n",
        "cloudformation": {"Big": _cf("AWS::Lambda::Function", MemorySize=4096, Timeout=900)},
        "terraform": 'resource "aws_lambda_function" "big" {\n  memory_size = 4096\n'
                     '  timeout = 900\n}\n',
    },
    "Fargate max": {
        "cdk": "new ecs.FargateTaskDefinition(this, 'Big', { cpu: 4096, memoryLimitMiB: 30720 });\n",
        "cloudformation": {"Big": _cf("AWS::ECS::TaskDefinition", Cpu="4096", Memory="30720")},
        "terraform": 'resource "aws_ecs_task_definition" "big" {\n  cpu = "4096"\n'
                     '  memory = "30720"\n}\n',
    },
    "Fargate 16 vCPU": {
        "cdk": "new ecs.FargateTaskDefinition(this, 'Big', { cpu: 16384, memoryLimitMiB: 65536 });\n",
        "cloudformation": {"Big": _cf("AWS::ECS::TaskDefinition", Cpu="16384", Memory="65536")},
        "terraform": 'resource "aws_ecs_task_definition" "big" {\n  cpu = 16384\n'
                     '  memory = 65536\n}\n',
    },
}
MID = {
    "cdk": "new lambda.Function(this, 'Mid', { memorySize: 1024, timeout: Duration.seconds(30) });\n"
           "new ecs.FargateTaskDefinition(this, 'T', { cpu: 1024, memoryLimitMiB: 4096 });\n",
    "cloudformation": {
        "Mid": _cf("AWS::Lambda::Function", MemorySize=1024, Timeout=30),
        "T": _cf("AWS::ECS::TaskDefinition", Cpu="1024", Memory="4096"),
    },
    "terraform": 'resource "aws_lambda_function" "mid" {\n  memory_size = 1024\n  timeout = 30\n}\n'
                 'resource "aws_ecs_task_definition" "t" {\n  cpu = "1024"\n  memory = "4096"\n}\n',
}
PROFILERS = {
    "CodeGuru": {
        "cdk": "new codeguruprofiler.ProfilingGroup(this, 'P');\n",
        "cloudformation": {"P": _cf("AWS::CodeGuruProfiler::ProfilingGroup",
                                    ProfilingGroupName="p")},
        "terraform": 'resource "aws_codeguruprofiler_profiling_group" "p" {\n  name = "p"\n}\n',
    },
    "Lambda Insights": {
        "cdk": "lambdaInsightsVersion: lambda.LambdaInsightsVersion.VERSION_1_0_229_0,\n",
        "cloudformation": {"L": _cf("AWS::Lambda::LayerVersion", Description="LambdaInsightsExtension")},
        "terraform": 'locals { layer = "arn:aws:lambda:eu-west-1:1:layer:LambdaInsightsExtension:38" }\n',
    },
    "Power Tuning": {
        "cdk": "new sam.CfnApplication(this, 'PT', { location: { applicationId: "
               "'arn:aws:serverlessrepo:us-east-1:1:applications/aws-lambda-power-tuning' } });\n",
        "cloudformation": {"PT": _cf("AWS::Serverless::Application", Location={
            "ApplicationId": "arn:aws:serverlessrepo:us-east-1:1:applications/"
                             "aws-lambda-power-tuning"})},
        "terraform": 'locals { app = "arn:aws:serverlessrepo:us-east-1:1:applications/'
                     'aws-lambda-power-tuning" }\n',
    },
}


@pytest.mark.parametrize("ceiling", tuple(CEILING))
@pytest.mark.parametrize("source", SOURCES)
def test_resource_ceiling_with_no_profile_fires_repo_104(
    tmp_path: Path, source: str, ceiling: str
) -> None:
    _stack(tmp_path, source, CEILING[ceiling][source])
    (hit,) = HotCodeUnprofiled().run(tmp_path)
    assert "Big" in hit.evidence or "big" in hit.evidence
    assert "CodeGuru Profiler" in hit.evidence and "found none" in hit.evidence


@pytest.mark.parametrize("profiler", tuple(PROFILERS))
@pytest.mark.parametrize("source", SOURCES)
def test_profiler_passes_repo_104(tmp_path: Path, source: str, profiler: str) -> None:
    _stack(tmp_path, source, CEILING["Lambda 10240"][source], PROFILERS[profiler][source])
    assert HotCodeUnprofiled().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_mid_size_compute_is_silent_repo_104(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, MID[source])
    assert HotCodeUnprofiled().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/load-test.md", "Ran k6: p99 420 ms at 800 rps; peak memory 3 GB."),
    ("docs/notes.md", "## Performance profile\n\nThe handler takes 2.5 seconds, 900 MB.\n"),
    ("docs/benchmark.md", "Benchmark: 1200 requests per run."),
))
def test_load_note_with_figures_passes_repo_104(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "terraform", CEILING["Lambda 10240"]["terraform"])
    _write(tmp_path / path, text)
    assert HotCodeUnprofiled().run(tmp_path) == []


def test_load_note_without_figures_still_fires_repo_104(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", CEILING["Lambda 10240"]["terraform"])
    _write(tmp_path / "docs/load-test.md", "We plan to load test soon.")
    assert len(HotCodeUnprofiled().run(tmp_path)) == 1
    _write(tmp_path / "docs/setup.md", "# Setup\n\nTakes 5 minutes, 200 ms.")
    assert len(HotCodeUnprofiled().run(tmp_path)) == 1


def test_timeout_alone_is_not_a_ceiling_repo_104(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation",
           {"F": _cf("AWS::Lambda::Function", MemorySize=512, Timeout=900)})
    assert HotCodeUnprofiled().run(tmp_path) == []


def test_python_cdk_repo_104(tmp_path: Path) -> None:
    _write(tmp_path / "prod/stack.py",
           "big = _lambda.Function(self, 'Big', memory_size=10240,\n"
           "                       timeout=Duration.minutes(5))\n"
           "NOTE = \"_lambda.Function(self, 'X', memory_size=10240)\"\n")
    (hit,) = HotCodeUnprofiled().run(tmp_path)
    assert "big" in hit.evidence and "10240" in hit.evidence
    _write(tmp_path / "prod/stack.py", "NOTE = \"_lambda.Function(self, 'X', memory_size=10240)\"\n")
    assert HotCodeUnprofiled().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_is_skipped_repo_104(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", CEILING["Lambda 10240"]["terraform"], env=env)
    assert HotCodeUnprofiled().run(tmp_path) == []


# REPO-105: end-user devices.

MOBILE = {
    "android": ("app/src/main/AndroidManifest.xml", "<manifest package='a.b'/>"),
    "xcodeproj": ("ios/App.xcodeproj/project.pbxproj", "// !$*UTF8*$!"),
    "xcworkspace": ("ios/App.xcworkspace/contents.xcworkspacedata", "<Workspace/>"),
    "plist": ("ios/App/Info.plist", "<plist/>"),
    "flutter": ("app/pubspec.yaml", "dependencies:\n  flutter:\n    sdk: flutter\n"),
    "expo": ("app/app.json", '{"expo": {"name": "x"}}'),
    "react-native": ("app/package.json", '{"dependencies": {"react-native": "0.74"}}'),
    "expo package": ("app/package.json", '{"dependencies": {"expo": "51"}}'),
    "capacitor": ("app/capacitor.config.ts", "export default {}"),
    "cordova": ("app/config.xml", "<widget id='a.b'/>"),
}
DEVICE_IAC = {
    "iot": {
        "cdk": "new iot.CfnThing(this, 'Sensor');\n",
        "cloudformation": {"Sensor": _cf("AWS::IoT::Thing")},
        "terraform": 'resource "aws_iot_thing" "sensor" {\n  name = "s"\n}\n',
    },
    "pinpoint": {
        "cdk": "new pinpoint.CfnApp(this, 'Push', { name: 'p' });\n",
        "cloudformation": {"Push": _cf("AWS::Pinpoint::App", Name="p")},
        "terraform": 'resource "aws_pinpoint_app" "push" {\n  name = "p"\n}\n',
    },
    "amplify mobile": {
        "cdk": "new amplify.CfnApp(this, 'App', { name: 'a', platform: 'iOS' });\n",
        "cloudformation": {"App": _cf("AWS::Amplify::App", Name="a", Description="iOS app")},
        "terraform": 'resource "aws_amplify_app" "app" {\n  name = "a"\n  platform = "iOS"\n}\n',
    },
}


@pytest.mark.parametrize("kind", tuple(MOBILE))
def test_mobile_sources_without_device_testing_fire_repo_105(tmp_path: Path, kind: str) -> None:
    path, text = MOBILE[kind]
    _write(tmp_path / path, text)
    (hit,) = DeviceImpactUnaddressed().run(tmp_path)
    assert path.split("/")[0] in hit.evidence and "found none" in hit.evidence


@pytest.mark.parametrize("kind", tuple(DEVICE_IAC))
@pytest.mark.parametrize("source", SOURCES)
def test_device_iac_without_testing_fires_repo_105(tmp_path: Path, source: str,
                                                   kind: str) -> None:
    _stack(tmp_path, source, DEVICE_IAC[kind][source])
    assert len(DeviceImpactUnaddressed().run(tmp_path)) == 1


def test_web_amplify_app_is_silent_repo_105(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {"App": _cf("AWS::Amplify::App", Platform="WEB")})
    assert DeviceImpactUnaddressed().run(tmp_path) == []


DEVICE_FARM = {
    "cdk": "new devicefarm.CfnProject(this, 'Farm', { name: 'f' });\n",
    "cloudformation": {"Farm": _cf("AWS::DeviceFarm::Project", Name="f")},
    "terraform": 'resource "aws_devicefarm_project" "farm" {\n  name = "f"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_device_farm_passes_repo_105(tmp_path: Path, source: str) -> None:
    _write(tmp_path / MOBILE["android"][0], MOBILE["android"][1])
    _stack(tmp_path, source, DEVICE_FARM[source])
    assert DeviceImpactUnaddressed().run(tmp_path) == []


def test_ci_device_farm_step_passes_repo_105(tmp_path: Path) -> None:
    _write(tmp_path / MOBILE["android"][0], MOBILE["android"][1])
    _write(tmp_path / ".github/workflows/ci.yml",
           "jobs:\n  t:\n    steps:\n      - run: aws devicefarm schedule-run --project-arn x\n")
    assert DeviceImpactUnaddressed().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/supported-devices.md", "Android 9 and up, iPhone 8 and up."),
    ("docs/notes.md", "## Minimum OS\n\niOS 15 and Android 10.\n"),
    ("docs/battery.md", "We cap background sync to save battery."),
    ("docs/notes.md", "# Hardware lifecycle\n\nSensors stay in service 8 years.\n"),
    ("docs/device-matrix.md", "Pixel 6, iPhone 12."),
))
def test_device_note_passes_repo_105(tmp_path: Path, path: str, text: str) -> None:
    _write(tmp_path / MOBILE["android"][0], MOBILE["android"][1])
    _write(tmp_path / path, text)
    assert DeviceImpactUnaddressed().run(tmp_path) == []


def test_unrelated_note_still_fires_repo_105(tmp_path: Path) -> None:
    _write(tmp_path / MOBILE["android"][0], MOBILE["android"][1])
    _write(tmp_path / "docs/setup.md", "# Setup\n\nRun the build.")
    assert len(DeviceImpactUnaddressed().run(tmp_path)) == 1


def test_server_side_repo_is_silent_repo_105(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", CEILING["Lambda 10240"]["terraform"])
    _write(tmp_path / "package.json", '{"dependencies": {"express": "4"}}')
    assert DeviceImpactUnaddressed().run(tmp_path) == []


def test_mobile_sources_in_tests_and_node_modules_are_skipped_repo_105(tmp_path: Path) -> None:
    _write(tmp_path / "tests/app/AndroidManifest.xml", "<manifest/>")
    _write(tmp_path / "node_modules/x/AndroidManifest.xml", "<manifest/>")
    assert DeviceImpactUnaddressed().run(tmp_path) == []


# REPO-106: data access patterns (REPO-063 detection).

@pytest.mark.parametrize("source", SOURCES)
def test_instance_only_data_fires_repo_106(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, INSTANCE[source], EBS_VOLUME[source])
    (hit,) = DataAccessPatternMismatch().run(tmp_path)
    assert "access pattern" in hit.evidence and "found none" in hit.evidence
    assert hit.category == "Sustainability"


@pytest.mark.parametrize("source", SOURCES)
def test_repo_106_matches_repo_063(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, INSTANCE[source], EBS_VOLUME[source])
    (old,) = PurposeBuiltDataStoreMissing().run(tmp_path)
    (new,) = DataAccessPatternMismatch().run(tmp_path)
    assert (old.file, old.line) == (new.file, new.line)
    assert old.category == "Performance Efficiency"
    assert "managed data store (S3, DynamoDB, RDS or Aurora" in old.evidence
    assert old.evidence.startswith("Keeps data on the instance: ")


def test_managed_store_passes_repo_106(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", EBS_VOLUME["terraform"],
           'resource "aws_dynamodb_table" "t" {\n  name = "t"\n}\n')
    assert DataAccessPatternMismatch().run(tmp_path) == []
    assert PurposeBuiltDataStoreMissing().run(tmp_path) == []


def test_database_engine_on_the_host_fires_repo_106(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform",
           'resource "aws_instance" "db" {\n  user_data = "yum install -y mysql-server"\n}\n')
    assert len(DataAccessPatternMismatch().run(tmp_path)) == 1
    assert len(PurposeBuiltDataStoreMissing().run(tmp_path)) == 1


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_dev_volume_does_not_fire_repo_106(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", EBS_VOLUME["terraform"], env=env)
    assert DataAccessPatternMismatch().run(tmp_path) == []


def test_python_cdk_volume_fires_repo_106(tmp_path: Path) -> None:
    _write(tmp_path / "prod/stack.py",
           "vol = ec2.Volume(self, 'Data', availability_zone='a', size=Size.gibibytes(500))\n"
           "vol.grant_attach_volume(role)\n")
    assert len(DataAccessPatternMismatch().run(tmp_path)) == 1


# All four.

def test_every_rule_is_silent_on_this_repo() -> None:
    root = Path(__file__).resolve().parent.parent
    for rule in RULES:
        assert rule.run(root) == [], rule.id


def _firing(rule_id: str, root: Path) -> None:
    if rule_id == "REPO-103":
        _stack(root, "terraform", UNUSED["ECS service at 0"]["terraform"])
    elif rule_id == "REPO-104":
        _stack(root, "terraform", CEILING["Lambda 10240"]["terraform"])
    elif rule_id == "REPO-105":
        _write(root / MOBILE["android"][0], MOBILE["android"][1])
    else:
        _stack(root, "terraform", EBS_VOLUME["terraform"], INSTANCE["terraform"])


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path,
                                                                   rule) -> None:
    _firing(rule.id, tmp_path)
    (hit,) = rule.run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    text = f"# Load test\n{hit.title}\n{hit.evidence}\n{hit.recommendation}\n"
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "load-test.md",
           "# AWS Architecture Review Report\n\n" + text)
    assert len(rule.run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", "# AWS Architecture Review Report\n\n" + text)
    assert rule.run(empty) == []


@pytest.mark.parametrize("rule_id,practice", (
    ("REPO-103", "SUS03-BP02"), ("REPO-104", "SUS03-BP03"), ("REPO-105", "SUS03-BP04"),
    ("REPO-106", "SUS03-BP05"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "SUS 3"


def test_repo_063_keeps_its_mapping() -> None:
    assert well_architected.question_of("REPO-063") == "PERF 3"


def test_rules_run_by_default() -> None:
    assert {r.id for r in RULES} & ORG_RULE_IDS == set()
    assert {r.category for r in RULES} == {"Sustainability"}
    assert {r.severity for r in RULES} == {"Low"}
    assert {t for r in RULES for t in r.themes} == {"sustainability", "finops"}


def test_sus3_is_fully_checked() -> None:
    (sus3,) = [a for a in well_architected.answers([]) if a.question.id == "SUS 3"]
    assert sus3.not_checked == ()


def test_sus3_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _firing("REPO-103", tmp_path)
    findings = UnusedComponents().run(tmp_path)
    (sus3,) = [a for a in well_architected.answers(findings) if a.question.id == "SUS 3"]
    assert not sus3.met
