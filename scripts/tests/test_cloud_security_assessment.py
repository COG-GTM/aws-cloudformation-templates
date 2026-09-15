"""Regression tests for scripts/cloud_security_assessment.py and scripts/cloud_security_report.py.

Run with ``python3 -m pytest scripts/tests`` from the repository root. The tests exercise the parts of the runner
that do not shell out: template parsing (YAML with line numbers and JSON without), the custom rule pack, scanner
result normalization and merging, stable finding identities, baseline carry-forward and the report's systemic
pattern shares. External scanners are not executed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cloud_security_assessment as csa  # noqa: E402
import cloud_security_report as report  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------


def ctx_from_text(tmp_path: Path, name: str, text: str) -> csa.TemplateCtx:
    p = tmp_path / name
    p.write_text(text)
    data = csa.load_template(p)
    assert data is not None, f"{name} did not parse as a single mapping template"
    rel = f"Fixture/{name}"
    return csa.TemplateCtx(path=p, rel=rel, text=text, lines=text.splitlines(), data=data, service_dir=csa.service_dir_of(rel))


def rule_by_id(rule_id: str) -> csa.Rule:
    return next(r for r in csa.RULES if r.id == rule_id)


def hits(rule_id: str, ctx: csa.TemplateCtx) -> list[csa.Hit]:
    r = rule_by_id(rule_id)
    assert r.check is not None
    return list(r.check(ctx))


def finding(rule_id: str, rel: str, lid: str, **overrides) -> csa.Finding:
    r = rule_by_id(rule_id)
    base = dict(
        finding_id=csa.make_finding_id(rule_id, rel, lid), template_path=rel, service_directory=csa.service_dir_of(rel),
        resource_logical_id=lid, resource_type=r.applies_to[0], title=r.title, description=r.description,
        evidence=f"{rel}:1", evidence_file=rel, evidence_line=1, evidence_snippet="", severity=r.severity,
        severity_justification=csa.SEVERITY_JUSTIFICATION[r.severity], nist_controls=list(r.nist), cis_aws_v3_id=r.cis,
        dod_cloud_srg_area=csa.SRG_AREAS[r.area], source="custom", custom_rule_id=rule_id, checkov_ids=[], cfn_nag_ids=[],
        cfn_lint_ids=[], recommended_remediation=r.remediation, disposition="Open", disposition_note="", owner="x",
        target_date="TBD", tags=[],
    )
    base.update(overrides)
    return csa.Finding(**base)


BUCKET_YAML = """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Plain:
    Type: AWS::S3::Bucket
  EmptyEncryption:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption: {}
  RuleWithoutDefault:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
  Sse:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
  Cmk:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
              KMSMasterKeyID: !Ref Key
  Key:
    Type: AWS::KMS::Key
"""


# ---------------------------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------------------------


def test_yaml_nodes_carry_line_numbers(tmp_path: Path):
    ctx = ctx_from_text(tmp_path, "t.yaml", BUCKET_YAML)
    res = ctx.resources["EmptyEncryption"]
    assert ctx.resource_line("EmptyEncryption", res) == 6  # first line of the resource mapping
    assert ctx.prop_line("EmptyEncryption", res, "Properties", "BucketEncryption") == 8
    assert ctx.prop_line("EmptyEncryption", res, "Properties", "Missing") == 7  # deepest existing key


def test_json_prop_line_is_bounded_to_the_resource(tmp_path: Path):
    """A key that exists only in a later resource must not become evidence for an earlier one."""
    text = json.dumps({
        "Resources": {
            "First": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "a"}},
            "Second": {"Type": "AWS::S3::Bucket", "Properties": {"BucketEncryption": {}}},
        }
    }, indent=1)
    ctx = ctx_from_text(tmp_path, "t.json", text)
    first, second = ctx.resources["First"], ctx.resources["Second"]
    first_line = ctx.resource_line("First", first)
    second_line = ctx.resource_line("Second", second)
    assert first_line < second_line
    # BucketEncryption is absent from First: evidence stays inside First's range.
    line = ctx.prop_line("First", first, "Properties", "BucketEncryption")
    assert first_line <= line < second_line
    # Second's own BucketEncryption is found.
    line2 = ctx.prop_line("Second", second, "Properties", "BucketEncryption")
    assert line2 >= second_line and '"BucketEncryption"' in ctx.lines[line2 - 1]


def test_malformed_and_multi_document_files_are_not_templates(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("Resources: [unclosed\n")
    assert csa.load_template(bad) is None
    multi = tmp_path / "multi.yaml"
    multi.write_text("a: 1\n---\nb: 2\n")
    assert csa.load_template(multi) is None


def test_foreach_expansion_yields_one_resource_per_item():
    resources = {
        "Fn::ForEach::Buckets": ["Name", ["Logs", "Data"], {"${Name}Bucket": {"Type": "AWS::S3::Bucket"}}],
        "Fn::ForEach::Dynamic": ["N", {"Ref": "Names"}, {"${N}Queue": {"Type": "AWS::SQS::Queue"}}],
    }
    out = csa.expand_resources(resources)
    assert set(out) == {"LogsBucket", "DataBucket", "${N}Queue"}


# ---------------------------------------------------------------------------------------------
# custom rules
# ---------------------------------------------------------------------------------------------


def test_s3_encryption_rules_cover_absent_empty_and_malformed_blocks(tmp_path: Path):
    ctx = ctx_from_text(tmp_path, "t.yaml", BUCKET_YAML)
    enc001 = {h.logical_id: h.detail for h in hits("CSA-ENC-001", ctx)}
    enc002 = {h.logical_id for h in hits("CSA-ENC-002", ctx)}
    assert set(enc001) == {"Plain", "EmptyEncryption", "RuleWithoutDefault"}
    assert enc001["Plain"] == "Properties.BucketEncryption is absent"
    assert "no ServerSideEncryptionByDefault" in enc001["EmptyEncryption"]
    assert enc002 == {"Sse"}
    # A bucket is never reported by both rules and the CMK bucket by neither.
    assert not (set(enc001) & enc002)
    assert "Cmk" not in set(enc001) | enc002


def test_block_gap_rejects_empty_and_non_mapping_blocks():
    assert csa.block_gap({}, "LoggingConfiguration", "DestinationBucketName") == "Properties.LoggingConfiguration is absent"
    assert "does not set DestinationBucketName" in csa.block_gap({"LoggingConfiguration": {}}, "LoggingConfiguration", "DestinationBucketName")
    assert "not a mapping" in csa.block_gap({"VpcConfig": "x"}, "VpcConfig", "SubnetIds")
    assert csa.block_gap({"VpcConfig": {"SubnetIds": ["s"]}}, "VpcConfig", "SubnetIds") is None
    conditional = {"LoggingConfiguration": {"Fn::If": ["C", {"DestinationBucketName": "x"}, {"Ref": "AWS::NoValue"}]}}
    assert "Fn::If branch" in csa.block_gap(conditional, "LoggingConfiguration", "DestinationBucketName")
    both = {"LoggingConfiguration": {"Fn::If": ["C", {"DestinationBucketName": "x"}, {"DestinationBucketName": "y"}]}}
    assert csa.block_gap(both, "LoggingConfiguration", "DestinationBucketName") is None


def test_s3_logging_and_stream_encryption_use_block_contents(tmp_path: Path):
    text = """\
Resources:
  Silent:
    Type: AWS::S3::Bucket
    Properties:
      LoggingConfiguration: {}
  Logged:
    Type: AWS::S3::Bucket
    Properties:
      LoggingConfiguration:
        DestinationBucketName: logs
  Stream:
    Type: AWS::Kinesis::Stream
    Properties:
      StreamEncryption:
        EncryptionType: KMS
  Encrypted:
    Type: AWS::Kinesis::Stream
    Properties:
      StreamEncryption:
        EncryptionType: KMS
        KeyId: alias/x
"""
    ctx = ctx_from_text(tmp_path, "t.yaml", text)
    assert {h.logical_id for h in hits("CSA-LOG-001", ctx)} == {"Silent"}
    assert {h.logical_id for h in hits("CSA-ENC-009", ctx)} == {"Stream"}


def test_admin_ingress_rule_reports_each_open_port_with_a_stable_key(tmp_path: Path):
    text = """\
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: x
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
"""
    ctx = ctx_from_text(tmp_path, "t.yaml", text)
    got = hits("CSA-NET-001", ctx)
    assert len(got) == 2
    assert all(h.key for h in got)
    ids = {csa.make_finding_id("CSA-NET-001", ctx.rel, "Sg", h.key or "") for h in got}
    assert len(ids) == 2


def test_every_rule_declares_traceability():
    for r in csa.RULES:
        assert r.nist, r.id
        assert all(c in csa.NIST_CONTROLS for c in r.nist), r.id
        assert r.area in csa.SRG_AREAS, r.id
        assert r.applies_to, r.id
        assert r.severity in csa.SEVERITY_ORDER, r.id


def test_rule_pack_runs_on_a_repository_template_with_evidence_lines():
    t = REPO / "S3" / "S3_LambdaTrigger.yaml"
    if not t.exists():
        pytest.skip("repository template not present")
    findings, _types, _counts, _hits, parsed, failures = csa.assess_templates(REPO, [t])
    assert parsed and not failures
    assert findings
    for f in findings:
        assert f.evidence_line >= 1 and f.nist_controls and f.finding_id


# ---------------------------------------------------------------------------------------------
# scanner normalization and merge
# ---------------------------------------------------------------------------------------------


def test_checkov_report_normalization():
    data = {"check_type": "cloudformation", "results": {"failed_checks": [
        {"file_path": "/S3/b.yaml", "resource": "AWS::S3::Bucket.Bucket", "check_id": "CKV_AWS_18",
         "file_line_range": [7, 12], "check": {"name": "Ensure the S3 bucket has access logging enabled"}, "guideline": "https://x"},
    ]}}
    (h,) = csa.checkov_hits_from_report(data)
    assert (h.source, h.check_id, h.rel, h.logical_id, h.resource_type, h.line) == ("checkov", "CKV_AWS_18", "S3/b.yaml", "Bucket", "AWS::S3::Bucket", 7)


def test_cfn_lint_normalization_keeps_property_path_as_discriminator():
    data = [
        {"Level": "Warning", "Rule": {"Id": "W1"}, "Filename": "./EC2/a.yaml", "Location": {"Path": ["Resources", "I"]}},
        {"Level": "Error", "Rule": {"Id": "E3012", "ShortDescription": "Type"}, "Filename": "./EC2/a.yaml", "Message": "m1",
         "Location": {"Path": ["Resources", "I", "Properties", "A"], "Start": {"LineNumber": 10}}},
        {"Level": "Error", "Rule": {"Id": "E3012", "ShortDescription": "Type"}, "Filename": "./EC2/a.yaml", "Message": "m2",
         "Location": {"Path": ["Resources", "I", "Properties", "B"], "Start": {"LineNumber": 14}}},
    ]
    got, warnings = csa.cfn_lint_hits_from_output(data)
    assert warnings == 1
    assert [h.discriminator for h in got] == ["Properties/A", "Properties/B"]
    assert all(h.rel == "EC2/a.yaml" and h.logical_id == "I" for h in got)


def test_repeated_scanner_violations_stay_distinct_and_exact_duplicates_collapse():
    rel, lid = "EC2/a.yaml", "Sg"
    ext = [
        csa.ExternalHit("cfn_nag", "W9", "wide cidr", rel, lid, "", 12, message="a"),
        csa.ExternalHit("cfn_nag", "W9", "wide cidr", rel, lid, "", 20, message="b"),
        csa.ExternalHit("cfn_nag", "W9", "wide cidr", rel, lid, "", 20, message="b"),  # exact duplicate
        csa.ExternalHit("cfn-lint", "E3012", "Type", rel, lid, "", 10, message="m1", discriminator="Properties/A"),
        csa.ExternalHit("cfn-lint", "E3012", "Type", rel, lid, "", 14, message="m2", discriminator="Properties/B"),
    ]
    merged = csa.merge_external([], ext, REPO, {(rel, lid): "AWS::EC2::SecurityGroup"}, {rel})
    assert len(merged) == 4
    assert len({f.finding_id for f in merged}) == 4
    # A lone violation without a discriminator keeps the plain identity, so its ID is stable across runs.
    (single,) = csa.merge_external([], ext[:1], REPO, {(rel, lid): "AWS::EC2::SecurityGroup"}, {rel})
    assert single.finding_id == csa.make_finding_id("W9", rel, lid)


def test_scanner_hit_attaches_to_the_matching_custom_finding():
    rel, lid = "S3/b.yaml", "Bucket"
    custom = [finding("CSA-LOG-001", rel, lid)]
    ext = [csa.ExternalHit("checkov", "CKV_AWS_18", "logging", rel, lid, "AWS::S3::Bucket", 3)]
    merged = csa.merge_external(custom, ext, REPO, {(rel, lid): "AWS::S3::Bucket"}, {rel})
    assert len(merged) == 1 and merged[0].checkov_ids == ["CKV_AWS_18"]


def test_port_specific_checks_attach_only_to_the_covering_ingress():
    assert csa.ingress_key_covers_port("0.0.0.0/0|22-22/tcp", 22)
    assert not csa.ingress_key_covers_port("0.0.0.0/0|3389-3389/tcp", 22)
    assert csa.ingress_key_covers_port("0.0.0.0/0|-1--1/-1", 3389)
    assert not csa.ingress_key_covers_port("0.0.0.0/0|22-22/udp", 22)


# ---------------------------------------------------------------------------------------------
# stable identities and baseline carry-forward
# ---------------------------------------------------------------------------------------------


def test_finding_ids_depend_only_on_rule_template_resource_and_discriminator():
    a = csa.make_finding_id("CSA-ENC-001", "S3/a.yaml", "B")
    assert a == csa.make_finding_id("CSA-ENC-001", "S3/a.yaml", "B")
    assert a != csa.make_finding_id("CSA-ENC-001", "S3/a.yaml", "C")
    assert a != csa.make_finding_id("CSA-ENC-001", "S3/a.yaml", "B", "k")
    assert a.startswith("CSA-ENC-001-")


def test_finding_round_trips_and_tolerates_schema_evolution():
    f = finding("CSA-ENC-001", "S3/a.yaml", "B")
    d = f.to_dict()
    assert csa.finding_from_dict(d) == f
    older = {k: v for k, v in d.items() if k not in ("risk_score", "risk_rank", "hit_key")}  # fields with defaults
    assert csa.finding_from_dict(older) == f
    newer = dict(d, future_field="x")
    assert csa.finding_from_dict(newer) == f
    assert csa.finding_from_dict({k: v for k, v in d.items() if k != "severity"}) is None


def test_baseline_carry_forward_marks_remediated_only_when_re_evaluated(tmp_path: Path, capsys):
    rel = "S3/a.yaml"
    gone = finding("CSA-ENC-001", rel, "Gone")
    still = finding("CSA-ENC-001", rel, "Still")
    not_rescanned = finding("CSA-ENC-001", "S3/unparsed.yaml", "X")
    broken = {k: v for k, v in finding("CSA-ENC-001", rel, "Broken").to_dict().items() if k != "title"}
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({
        "metadata": {"commit_sha": "abc123", "schema_version": csa.FINDINGS_SCHEMA_VERSION},
        "summary": {"open_findings": 4},
        "findings": [gone.to_dict(), still.to_dict(), not_rescanned.to_dict(), broken],
    }))
    tools = [csa.ToolResult("checkov", "x", "ran"), csa.ToolResult("cfn_nag", "x", "ran"), csa.ToolResult("cfn-lint", "x", "ran")]
    out, before = csa.apply_baseline([still], baseline, None, tools, {rel}, {})
    assert before == {"open_findings": 4}
    by_id = {f.finding_id: f for f in out}
    assert by_id[still.finding_id].disposition == "Open"
    assert by_id[gone.finding_id].disposition == "Remediated in PR"
    assert by_id[not_rescanned.finding_id].disposition == "Open"
    assert "Not re-evaluated" in by_id[not_rescanned.finding_id].disposition_note
    assert not any(f.resource_logical_id == "Broken" for f in out)
    assert "1 baseline row(s) lack a required Finding field" in capsys.readouterr().err


def test_baseline_schema_mismatch_is_reported(tmp_path: Path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"metadata": {"commit_sha": "abc"}, "summary": {}, "findings": []}))
    csa.apply_baseline([], baseline, None, [], set(), {})
    assert "findings schema None" in capsys.readouterr().err


# ---------------------------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------------------------


def test_systemic_pattern_rules_exist_and_shares_count_unique_resources():
    ids = {r.id for r in csa.RULES}
    assert all(rid in ids for _label, rid in report.PATTERNS)
    rows = [
        {"custom_rule_id": "CSA-NET-001", "template_path": "a", "resource_logical_id": "Sg"},
        {"custom_rule_id": "CSA-NET-001", "template_path": "a", "resource_logical_id": "Sg"},
        {"custom_rule_id": "CSA-NET-001", "template_path": "b", "resource_logical_id": "Sg"},
        {"custom_rule_id": "CSA-ENC-001", "template_path": "a", "resource_logical_id": "Sg"},
    ]
    assert report.affected_resources(rows, "CSA-NET-001") == 2


def test_committed_artifacts_are_internally_consistent():
    """The committed findings.json satisfies the traceability constraints the tracker is built on."""
    p = REPO / "security-assessment" / "findings.json"
    if not p.exists():
        pytest.skip("findings.json not generated")
    data = json.loads(p.read_text())
    rows = data["findings"]
    assert data["metadata"]["schema_version"] == csa.FINDINGS_SCHEMA_VERSION
    assert len({f["finding_id"] for f in rows}) == len(rows)
    assert all(f["nist_controls"] and f["evidence_line"] >= 1 for f in rows)
    assert data["summary"]["total_findings"] == len(rows)
    assert all(f["disposition"] in csa.DISPOSITIONS for f in rows)
