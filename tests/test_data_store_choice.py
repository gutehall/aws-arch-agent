"""PERF 3: storing, managing and accessing data. A purpose-built data store rather than data
kept on the instance (REPO-063)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import PurposeBuiltDataStoreMissing

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object, env: str = "prod") -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / env / _PATHS[source], body)


def _run(root: Path) -> list:
    return PurposeBuiltDataStoreMissing().run(root)


INSTANCE = {
    "cdk": "const host = new ec2.Instance(this, 'Db', { vpc, instanceType, machineImage });\n",
    "cloudformation": {"Db": {"Type": "AWS::EC2::Instance",
                              "Properties": {"InstanceType": "m7g.large"}}},
    "terraform": 'resource "aws_instance" "db" {\n  instance_type = "m7g.large"\n}\n',
}
EBS_VOLUME = {
    "cdk": "new ec2.Volume(this, 'Data', { availabilityZone: 'eu-west-1a', "
           "size: cdk.Size.gibibytes(500) });\n",
    "cloudformation": {
        "Data": {"Type": "AWS::EC2::Volume", "Properties": {"Size": 500}},
        "Attach": {"Type": "AWS::EC2::VolumeAttachment", "Properties": {"Device": "/dev/sdf"}},
    },
    "terraform": 'resource "aws_ebs_volume" "data" {\n  size = 500\n}\n'
                 'resource "aws_volume_attachment" "data" {\n  device_name = "/dev/sdf"\n}\n',
}
INSTANCE_STORE = {
    "cdk": "new ec2.Instance(this, 'Db', { vpc, instanceType, machineImage, blockDevices: [\n"
           "  { deviceName: '/dev/xvda', volume: ec2.BlockDeviceVolume.ebs(30) },\n"
           "  { deviceName: '/dev/xvdb', volume: ec2.BlockDeviceVolume.ephemeral(0) },\n"
           "] });\n",
    "cloudformation": {"Db": {"Type": "AWS::EC2::Instance", "Properties": {
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 30}},
                                {"VirtualName": "ephemeral0"}]}}},
    "terraform": 'resource "aws_instance" "db" {\n  ephemeral_block_device {\n'
                 '    virtual_name = "ephemeral0"\n  }\n}\n',
}
DB_ON_HOST = {
    "cdk": "const host = new ec2.Instance(this, 'Db', { vpc, instanceType, machineImage });\n"
           "host.userData.addCommands('dnf install -y postgresql15-server', "
           "'systemctl enable --now postgresql');\n",
    "cloudformation": {"Db": {"Type": "AWS::EC2::Instance", "Properties": {
        "UserData": {"Fn::Base64": "#!/bin/bash\nyum install -y mysql-server\n"}}}},
    "terraform": 'resource "aws_instance" "db" {\n  user_data = <<-EOF\n'
                 '    #!/bin/bash\n    docker run -d -p 6379:6379 redis:7\n  EOF\n}\n',
}
RDS = {
    "cdk": "new rds.DatabaseInstance(this, 'Db', { engine, vpc });\n",
    "cloudformation": {"Db": {"Type": "AWS::RDS::DBInstance", "Properties": {"Engine": "mysql"}}},
    "terraform": 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n',
}
DYNAMODB = {
    "cdk": "new dynamodb.TableV2(this, 'Items', { partitionKey });\n",
    "cloudformation": {"Items": {"Type": "AWS::DynamoDB::Table", "Properties": {}}},
    "terraform": 'resource "aws_dynamodb_table" "items" {\n  hash_key = "pk"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_ebs_only_data_fails_repo_063(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, INSTANCE[source], EBS_VOLUME[source])
    (finding,) = _run(tmp_path)
    assert finding.id == "REPO-063"
    assert finding.category == "Performance Efficiency"
    assert "EBS data volume at prod/" in finding.evidence
    assert "searched the IaC for a managed data store" in finding.evidence
    assert finding.evidence.endswith("found none")
    assert finding.file == f"prod/{_PATHS[source]}"
    assert finding.line


@pytest.mark.parametrize("store", (RDS, DYNAMODB), ids=("rds", "dynamodb"))
@pytest.mark.parametrize("source", SOURCES)
def test_ebs_with_managed_store_passes_repo_063(tmp_path: Path, source: str, store: dict) -> None:
    _stack(tmp_path, source, INSTANCE[source], EBS_VOLUME[source], store[source])
    assert _run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_database_engine_in_user_data_fails_repo_063(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, DB_ON_HOST[source])
    (finding,) = _run(tmp_path)
    engine = {"cdk": "postgresql15-server", "cloudformation": "mysql-server",
              "terraform": "redis"}[source]
    assert f"{engine} on the host" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_instance_store_fails_repo_063(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, INSTANCE_STORE[source])
    (finding,) = _run(tmp_path)
    assert "instance store volume" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_no_data_on_the_instance_passes_repo_063(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, INSTANCE[source])
    assert _run(tmp_path) == []


def test_root_volume_only_passes_repo_063(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {"Db": {"Type": "AWS::EC2::Instance", "Properties": {
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 30}}]}}})
    assert _run(tmp_path) == []


def test_client_only_and_engine_outside_user_data_pass_repo_063(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", INSTANCE["terraform"],
           '# docs: run mysql-server elsewhere\nlocals {\n  engine = "redis"\n}\n')
    _write(tmp_path / "prod" / "lib" / "app.ts",
           "host.userData.addCommands('yum install -y redis-tools python3-redis');\n")
    assert _run(tmp_path) == []


def test_python_cdk_ebs_volume_fails_repo_063(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "ec2.Instance(self, 'Db', vpc=vpc, instance_type=t, machine_image=ami)\n"
           "ec2.Volume(self, 'Data', availability_zone='eu-west-1a', "
           "size=Size.gibibytes(500))\n")
    (finding,) = _run(tmp_path)
    assert "EBS data volume at prod/stack.py:2" in finding.evidence


def test_python_cdk_with_bucket_passes_repo_063(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "ec2.Volume(self, 'Data', availability_zone='eu-west-1a', size=s)\n"
           "s3.Bucket(self, 'Objects')\n")
    assert _run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_dev_data_volume_does_not_fire_repo_063(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", INSTANCE["terraform"], EBS_VOLUME["terraform"], env=env)
    assert _run(tmp_path) == []


def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", INSTANCE["terraform"], EBS_VOLUME["terraform"])
    (hit,) = _run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    text = f"{hit.title}\n{hit.evidence}\n{hit.recommendation}\n"
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", text)
    assert len(_run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", text)
    assert _run(empty) == []


def test_rule_maps_to_perf3_and_runs_by_default() -> None:
    assert well_architected.best_practices_of("REPO-063") == ("PERF03-BP01",)
    assert "REPO-063" not in ORG_RULE_IDS


def test_perf3_is_fully_checked() -> None:
    (perf3,) = [a for a in well_architected.answers([]) if a.question.id == "PERF 3"]
    assert perf3.not_checked == ()


def test_perf3_is_not_met_when_the_rule_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", INSTANCE["terraform"], EBS_VOLUME["terraform"])
    findings = _run(tmp_path)
    (perf3,) = [a for a in well_architected.answers(findings) if a.question.id == "PERF 3"]
    assert not perf3.met


def test_engine_named_in_a_later_command_does_not_fire_repo_063(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {"App": {"Type": "AWS::EC2::Instance", "Properties": {
        "UserData": {"Fn::Base64": "#!/bin/bash\nyum install -y git\necho redis > /etc/motd\n"
                     "yum install -y nginx; echo mysql-server\n"}}}})
    assert _run(tmp_path) == []
