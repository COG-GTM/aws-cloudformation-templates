#!/usr/bin/env python3
"""Render security-assessment/Cloud-Security-Assessment-Report.md from findings.json.

Every count, table and list in the report is derived from the findings file written
by scripts/cloud_security_assessment.py so the narrative cannot drift from the data.
Run after the assessment:

    python3 scripts/cloud_security_assessment.py
    python3 scripts/cloud_security_report.py
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cloud_security_assessment as csa  # noqa: E402

SEVERITIES = (csa.CAT_I, csa.CAT_II, csa.CAT_III)

# Verified 2026-09-14 (HTTP 200).
REFERENCES = [
    ("NIST SP 800-53 Rev. 5 (with update 1), Security and Privacy Controls for Information Systems and Organizations",
     "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"),
    ("CIS Amazon Web Services Foundations Benchmark (v3.0.0 recommendation IDs are used in this report)",
     "https://www.cisecurity.org/benchmark/amazon_web_services"),
    ("AWS Security Hub — CIS AWS Foundations Benchmark controls (source of the v3.0.0 recommendation-to-control mapping)",
     "https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html"),
    ("DoD Cloud Computing Security Requirements Guide and Cloud Computing Mission Owner SRG (DISA Cyber Exchange, DCCS documents)",
     "https://public.cyber.mil/dccs/dccs-documents/"),
    ("Checkov", "https://github.com/bridgecrewio/checkov"),
    ("cfn_nag", "https://github.com/stelligent/cfn_nag"),
    ("cfn-lint", "https://github.com/aws-cloudformation/cfn-lint"),
    ("Rain (CloudFormation packaging and module tool used by this repository)", "https://github.com/aws-cloudformation/rain"),
]

# Systemic-pattern probes: (label, custom rule id). The share is affected resources (unique template + logical ID
# pairs with an open finding from the rule) over the resources of the types the rule applies to, both taken from
# findings.json so the denominator follows the rule's own ``applies_to`` metadata.
PATTERNS = [
    ("S3 buckets without declared server-side encryption", "CSA-ENC-001"),
    ("S3 buckets without an aws:SecureTransport deny policy", "CSA-TLS-001"),
    ("S3 buckets without a Public Access Block", "CSA-NET-007"),
    ("S3 buckets without server access logging", "CSA-LOG-001"),
    ("EC2 instances, launch templates and launch configurations without IMDSv2 required", "CSA-CFG-001"),
    ("EC2 volumes, instances, launch templates and launch configurations with unencrypted block storage", "CSA-ENC-004"),
    ("Database clusters and instances without storage encryption", "CSA-ENC-003"),
    ("VPCs without a flow log", "CSA-LOG-002"),
    ("Load balancers without access logging", "CSA-LOG-003"),
    ("Security groups with administrative ports open to the Internet (all severities)", "CSA-NET-001"),
    ("IAM roles without a permissions boundary", "CSA-IAM-007"),
    ("IAM roles with inline policies", "CSA-IAM-006"),
    ("IAM principals and policies granting write actions on Resource *", "CSA-IAM-003"),
    ("Stateful resources without deletion protection or a Retain policy", "CSA-BKP-002"),
    ("Lambda functions without active tracing", "CSA-MON-001"),
]


def affected_resources(findings: list[dict], rid: str) -> int:
    return len({(f["template_path"], f["resource_logical_id"]) for f in findings if f["custom_rule_id"] == rid})


def md_escape(s: str) -> str:
    """Table cells must not contain pipes; NIST enhancement titles use ' | ' as a separator."""
    return str(s).replace(" | ", " / ").replace("|", "/").replace("\n", " ")


def table(headers: list[str], rows: list[list[object]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(md_escape(c) for c in r) + " |")
    return "\n".join(out)


def sev_counts(findings: list[dict], only_open: bool = True) -> Counter:
    return Counter(f["severity"] for f in findings if (f["disposition"] == "Open" or not only_open))


def pct(n: int, d: int) -> str:
    return f"{(100 * n / d):.0f}%" if d else "n/a"


def build(data: dict) -> str:
    meta, summary, cov = data["metadata"], data["summary"], data["control_coverage"]
    findings: list[dict] = data["findings"]
    before = data.get("before_remediation")
    open_f = [f for f in findings if f["disposition"] == "Open"]
    remediated = [f for f in findings if f["disposition"] == "Remediated in PR"]
    risk_acc = [f for f in findings if f["disposition"] == "Risk acceptance recommended"]
    sev = sev_counts(findings)
    tools = {t["name"]: t for t in meta["tools"]}
    rules = {r["id"]: r for r in meta["custom_rules"]}
    type_counts: dict[str, int] = meta["resource_type_counts"]
    n_templates = meta["templates_assessed"]
    sha = meta["commit_sha"]
    top = sorted(open_f, key=lambda f: f["risk_rank"])[:20]
    n_tf = meta.get("terraform_files", 0)

    def dominant(sev_name: str, k: int = 4) -> str:
        """Comma list of the most frequent open finding titles at a severity, lower-cased for prose."""
        c = Counter(f["title"] for f in open_f if f["severity"] == sev_name)
        return "; ".join(f"{t[0].lower() + t[1:]} ({n})" for t, n in c.most_common(k))

    ran = [t for t in meta["tools"] if t["status"] == "ran"]
    not_ran = [t for t in meta["tools"] if t["status"] != "ran"]
    partial = [t for t in ran if t["unparsed"]]
    tool_names = {"checkov": "Checkov", "cfn_nag": "cfn_nag", "cfn-lint": "cfn-lint"}

    def tool_label(t: dict) -> str:
        v = t["version"]
        return v if v.lower().startswith(tool_names[t["name"]].lower()) else f"{tool_names[t['name']]} {v}"

    complete = [t for t in ran if not t["unparsed"] and not t["excluded"]]
    scanner_sentence = (f"{len(ran)} open-source scanner{'s' if len(ran) != 1 else ''} ({', '.join(tool_label(t) for t in ran)}) and a custom rule pack of {len(rules)} checks were run against the {n_templates} templates."
                        if ran else f"A custom rule pack of {len(rules)} checks was run against the {n_templates} templates; no external scanner ran.")
    if not_ran:
        scanner_sentence += " " + "; ".join(f"{tool_names[t['name']]} was {t['status']} ({t['note']})" for t in not_ran) + "."
    if partial:
        scanner_sentence += (" " + (", ".join(tool_names[t["name"]] for t in complete) + " processed every template; " if complete else "")
                             + "; ".join(f"{tool_names[t['name']]} did not process {len(t['unparsed'])} template(s)" for t in partial)
                             + " (listed in the Method sheet); those templates are covered by the custom rule pack and the remaining scanners only.")
    excluded = [t for t in ran if t["excluded"]]
    if excluded:
        scanner_sentence += " " + "; ".join(f"{tool_names[t['name']]} deliberately excluded {len(t['excluded'])} template(s) under the repository's lint conventions (scripts/lint-single.sh)" for t in excluded) + "."
    if n_tf:
        tf_scope = (f"{n_tf} Terraform `.tf` file(s) were discovered and scanned with Checkov." if tools["checkov"]["status"] == "ran"
                    else f"{n_tf} Terraform `.tf` file(s) were discovered but not scanned because Checkov was {tools['checkov']['status']}.")
    else:
        tf_scope = "No Terraform sources exist in this revision, so the Terraform portion of the tasking is not applicable. The runner scans `.tf` files automatically when they are added."
    cat1_open = [f for f in open_f if f["severity"] == csa.CAT_I]

    by_family: dict[str, list[dict]] = defaultdict(list)
    for f in open_f:
        for fam in f["nist_control_families"]:
            by_family[fam].append(f)

    templates_with_findings = len({f["template_path"] for f in findings})
    custom_count = sum(1 for f in findings if f["custom_rule_id"])
    tool_only = sum(1 for f in findings if not f["custom_rule_id"])

    L: list[str] = []
    A = L.append

    A("# Cloud Security Assessment Report")
    A("")
    tsha = meta.get("templates_commit_sha", "unknown")
    dirty = meta.get("templates_with_uncommitted_edits", 0)
    provenance = (f"The assessed templates were last changed in commit `{tsha}`; later commits on this branch (including the commit that "
                  f"adds these generated artifacts) do not change any assessed template." if tsha != "unknown" else "")
    if dirty:
        provenance += f" {dirty} assessed template(s) had uncommitted edits at scan time."
    A(f"Infrastructure-as-code baseline: CloudFormation templates in this repository at commit `{sha}` (branch `{meta['branch']}`), "
      f"assessed {meta['scan_date']}. {provenance} Prepared in the form of CDRL A008, Cloud Security Assessment Report, for the Government and the system owner.".replace("  ", " "))
    A("")

    # ------------------------------------------------------------------ 1
    A("## 1. Executive summary")
    A("")
    A(f"This assessment treats the {n_templates} CloudFormation templates in the repository as the infrastructure-as-code baseline for a set of Government cloud workloads. "
      f"{scanner_sentence} Each result was normalized into one schema, mapped to NIST SP 800-53 Rev. 5 controls, the CIS AWS Foundations Benchmark v3.0 "
      f"where a recommendation exists, and a DoD Cloud Computing SRG topic area, and assigned a DISA-style severity (CAT I, CAT II, CAT III) with a one-line justification.")
    A("")
    A(f"The scan produced {len(findings)} findings in {templates_with_findings} of {n_templates} templates. {len(open_f)} findings are open, {len(remediated)} are marked Remediated in PR, "
      f"and {len(risk_acc)} are recommended for risk acceptance.")
    A("")
    rows = [[s, sev[s], sum(1 for f in remediated if f["severity"] == s), sum(1 for f in risk_acc if f["severity"] == s),
             sum(1 for f in findings if f["severity"] == s)] for s in SEVERITIES]
    rows.append(["Total", len(open_f), len(remediated), len(risk_acc), len(findings)])
    A(table(["Severity", "Open", "Remediated in PR", "Risk acceptance recommended", "All findings"], rows))
    A("")
    if before:
        b = before["open_by_severity"]
        A("Before-and-after comparison with the assessment baseline (PR 1):")
        A("")
        A(table(["Severity", "Open before remediation", "Open after remediation", "Change"],
                [[s, b.get(s, 0), sev[s], sev[s] - b.get(s, 0)] for s in SEVERITIES]
                + [["Total", before["open_findings"], len(open_f), len(open_f) - before["open_findings"]]]))
        A("")
    A("Key results:")
    A("")
    if sev[csa.CAT_I]:
        A(f"- {sev[csa.CAT_I]} open CAT I findings: {dominant(csa.CAT_I)}. They head the risk-ranked list in section 3 and are the first remediation targets.")
    else:
        A(f"- No open CAT I findings. {len([f for f in remediated if f['severity'] == csa.CAT_I])} CAT I findings from the baseline are marked Remediated in PR.")
    A(f"- {sev[csa.CAT_II]} open CAT II findings, dominated by: {dominant(csa.CAT_II)}.")
    A(f"- {sev[csa.CAT_III]} open CAT III findings, dominated by: {dominant(csa.CAT_III)}.")
    A("- The dominant systemic pattern is the absence of secure defaults. The same weakness recurs across service directories because each template was written independently; section 5 quantifies this and section 6 recommends automation that prevents it.")
    A(f"- {tf_scope}")
    A("")

    # ------------------------------------------------------------------ 2
    A("## 2. Scope and method")
    A("")
    A("### 2.1 Scope")
    A("")
    twins = meta["generated_json_twins"]
    A(f"- {n_templates} CloudFormation templates (`.yaml`, `.yml`, `.json`, `.template` files with a `Resources` section) across {len(summary['open_by_service_directory'])} service directories with open findings. "
      f"{meta['skipped_files']} candidate files were skipped because they are not CloudFormation templates (for example Lambda source, policy fragments, configuration files)."
      + (f" {len(meta['malformed_files'])} file(s) with a template extension are not well-formed JSON/YAML and were not assessed by any scanner: "
         + ", ".join(f"`{p}`" for p in meta["malformed_files"]) + "." if meta.get("malformed_files") else " Every file with a template extension was well-formed JSON or YAML."))
    if meta.get("custom_rule_failures"):
        A("- Custom rules that raised an error and produced no result: " + "; ".join(f"`{p}` ({', '.join(ids)})" for p, ids in sorted(meta["custom_rule_failures"].items())) + ". Those template and rule pairs are coverage gaps.")
    A(f"- {len(twins)} JSON templates are generated twins of a YAML source in the same directory. YAML is the source of truth in this repository, so twins are not assessed separately (that would double every finding); "
      f"each twin is compared with its source and drift is reported as finding `CSA-CFG-002`. Use `--include-generated-json` to assess twins as independent templates."
      + (f" {len(meta.get('generated_json_not_compared', []))} twin(s) could not be compared because the twin or its source did not parse: "
         + ", ".join(f"`{p}`" for p in meta["generated_json_not_compared"]) + "." if meta.get("generated_json_not_compared") else " Every twin was compared with its source."))
    A(f"- Terraform: {n_tf} `.tf` files found. " + ("Scanned with Checkov (Terraform framework); the custom rule pack is CloudFormation-only." if n_tf else "Not applicable to this revision."))
    A("- Static analysis only. No deployed-account evidence (AWS Config, Security Hub, CloudTrail) was available or used. Parameter values are evaluated from their template defaults.")
    A("")
    A("### 2.2 Tools and versions")
    A("")
    A(table(["Tool", "Version", "Status", "Raw results", "Note"],
            [[t["name"], t["version"], t["status"], t["raw_count"], t["note"][:220] + ("…" if len(t["note"]) > 220 else "")] for t in meta["tools"]]))
    A("")
    A(f"The custom rule pack (`scripts/cloud_security_assessment.py`, rule IDs `CSA-*`) adds {len(rules)} checks for conditions the scanners miss or that the Government baseline emphasizes: "
      "encryption at rest for every storage, database, queue, topic, stream and log resource; customer-managed versus AWS-managed KMS keys; TLS enforcement in transit; public exposure; "
      "logging and monitoring; IAM least privilege; IMDSv2; secrets handling; backup, retention and deletion protection.")
    A("")
    A("### 2.3 Normalization, severity and ranking")
    A("")
    A(f"- Every result carries file and line evidence, at least one NIST SP 800-53 Rev. 5 control, a DoD Cloud Computing SRG area, tool and rule IDs, a recommended remediation and a disposition. {custom_count} findings come from the custom rule pack (of which many are corroborated by Checkov or cfn_nag on the same resource) and {tool_only} are tool-only findings.")
    A("- CAT I (direct and immediate loss of confidentiality, integrity or availability) is assigned only when the custom rule pack verified the exact condition on the parsed template. Tool-only results that depend on pattern heuristics are capped at CAT II. A cfn_nag result that repeats an equivalent Checkov check on the same resource is merged so a weakness is counted once.")
    A("- Risk rank 1 is the highest risk. The score is the severity base (CAT I 300, CAT II 200, CAT III 100) plus modifiers for Internet exposure, credential material, data stores, corroborating tools and core service directories. Open findings rank ahead of closed ones.")
    A("- CIS AWS Foundations Benchmark v3.0.0 IDs are cited only where the AWS Security Hub CIS v3.0.0 control mapping confirms a matching recommendation. No IAM benchmark IDs are cited for template-level IAM findings because the benchmark's IAM section addresses account-level settings.")
    A("")

    # ------------------------------------------------------------------ 3
    A("## 3. Risk-ranked findings (top 20)")
    A("")
    A("The full list is in `Cloud-Security-Findings-Tracker.xlsx` (sheet `Findings`) and `findings.json`. Evidence is `template:line` in this repository at the commit above.")
    A("")
    A(table(["#", "Finding", "Evidence (template:line, resource) and traceability"],
            [[f["risk_rank"],
              f"{f['severity']} — {f['finding_id']}: {f['title']}",
              f"{f['evidence_file']}:{f['evidence_line']} `{f['resource_logical_id']}`. "
              f"NIST {', '.join(f['nist_controls'])}; CIS {f['cis_aws_v3_id'] or 'n/a'}; {f['tool_rule_id']}"] for f in top]))
    A("")
    A("Evidence detail for the open CAT I findings:")
    A("")
    for f in cat1_open:
        A(f"- **{f['finding_id']}** (rank {f['risk_rank']}) — `{f['evidence']}`. Snippet: `{f['evidence_snippet'].strip()}`. {f['severity_justification']} Remediation: {f['recommended_remediation']}")
    if not cat1_open:
        A("- No CAT I findings remain open.")
    A("")

    # ------------------------------------------------------------------ 4
    A("## 4. Findings by NIST SP 800-53 Rev. 5 control family")
    A("")
    A("A finding that maps to controls in two families is counted in both. Counts are open findings.")
    A("")
    fam_rows = []
    for fam, fl in sorted(by_family.items(), key=lambda kv: -len(kv[1])):
        c = Counter(f["severity"] for f in fl)
        ctrls = Counter(ctrl for f in fl for ctrl in f["nist_controls"] if csa.family_of(ctrl) == fam)
        fam_rows.append([fam, len(fl), c[csa.CAT_I], c[csa.CAT_II], c[csa.CAT_III], ", ".join(f"{k} ({v})" for k, v in ctrls.most_common(6))])
    A(table(["Control family", "Open", "CAT I", "CAT II", "CAT III", "Most-cited controls (count)"], fam_rows))
    A("")
    A("Control coverage (open findings per control and templates with at least one finding for that control) is in sheet `Control-Coverage`. The controls with the most templates affected:")
    A("")
    A(table(["Control", "Title", "Open findings", "Templates with findings / assessed"],
            [[c["control"], c["title"], c["open"], f"{c['templates_with_findings']} / {c['templates_assessed']}"]
             for c in sorted(cov, key=lambda c: -c["templates_with_findings"])[:10]]))
    A("")

    # ------------------------------------------------------------------ 5
    A("## 5. Systemic patterns")
    A("")
    A("The counts below compare open rule hits with the number of resources of the relevant type in the assessed templates. They show that the weaknesses are baseline defaults, not isolated mistakes."
      + (" Findings marked Remediated in PR are excluded from the affected count and shown in the last column." if remediated else ""))
    A("")
    prow = []
    for label, rid in PATTERNS:
        n = affected_resources(open_f, rid)
        fixed = affected_resources(remediated, rid)
        d = sum(type_counts.get(t, 0) for t in rules[rid]["applies_to"])
        if n > d:
            raise SystemExit(f"{rid}: {n} affected resources exceed the {d} resources of its applies_to types; "
                             "the rule's applies_to metadata is incomplete")
        if d:
            prow.append([label, f"{n} of {d}", pct(n, d), rid] + ([fixed] if remediated else []))
    A(table(["Pattern", "Affected resources (open)", "Share", "Rule"] + (["Remediated in PR"] if remediated else []), prow))
    A("")
    drift = [f for f in open_f if f["custom_rule_id"] == "CSA-CFG-002"]
    A(f"Other patterns: {len(drift)} generated JSON templates differ from their YAML source (`CSA-CFG-002`), so a reviewer reading the JSON may see a different security posture than the one deployed from YAML. "
      f"{sum(1 for f in open_f if f['custom_rule_id'] == 'CSA-NET-001' and f['severity'] == csa.CAT_II)} security groups expose administrative ports through a CIDR parameter whose default is `0.0.0.0/0`; the parameter exists but its default undoes it.")
    A("")

    # ------------------------------------------------------------------ 6
    A("## 6. Recommended secure-by-default automation")
    A("")
    A("- **Pre-commit gate.** Add `cfn-lint` and `checkov` (framework `cloudformation`, with this repository's `.cfnlintrc` and a Checkov config that fails on HIGH and CRITICAL) as pre-commit hooks so a template cannot be committed with an open CIDR on port 22, an unencrypted volume or a bucket without a Public Access Block.")
    A("- **CI policy-as-code.** Run `python3 scripts/cloud_security_assessment.py` in CI and fail the job when a CAT I finding is introduced (compare `findings.json` against the previous run with `--baseline`). Publish the tracker as a build artifact so the POA&M stays current without manual editing.")
    A("- **Reusable secure modules.** The repository already uses Rain modules (`RainModules/`). Extend them with hardened building blocks — an encrypted, logged, TLS-only S3 bucket; an IMDSv2-required launch template; a security group that takes a CIDR parameter with an `AllowedPattern` that rejects `/0`; an HTTPS listener with a TLS 1.2+ policy — and reference the module instead of repeating resource properties in each template.")
    A("- **Parameter constraints.** Every CIDR parameter should carry `AllowedPattern` and a non-open default (or no default). Every secret parameter should carry `NoEcho: true` or be replaced by a Secrets Manager dynamic reference.")
    A("- **Generated-file discipline.** Regenerate JSON twins from YAML in CI (`rain fmt` or the repository's packaging step) and fail when the checked-in twin drifts.")
    A("- **Account-level guardrails.** Enable default EBS encryption, S3 account-level Block Public Access and IMDSv2 defaults at the account or organization level so the template default no longer decides the outcome.")
    A("")

    # ------------------------------------------------------------------ 7
    A("## 7. Zero Trust and identity observations")
    A("")
    iam_open = [f for f in open_f if f["custom_rule_id"] and f["custom_rule_id"].startswith("CSA-IAM")]
    A(f"- {len(iam_open)} open IAM findings. Roles are created per template with inline policies and without permissions boundaries, and {sum(1 for f in iam_open if f['custom_rule_id'] == 'CSA-IAM-003')} policies allow write actions on `Resource: *`. "
      "In a Zero Trust model each workload identity should be scoped to the resources it owns and constrained by a permissions boundary set by the platform team.")
    A(f"- {sum(1 for f in open_f if f['custom_rule_id'] == 'CSA-CFG-001')} compute resources do not require IMDSv2. Without `HttpTokens: required`, an SSRF or local file-read weakness on the instance can steal the role credentials. This is the single most common identity-related weakness in the baseline.")
    A(f"- {sum(1 for f in open_f if f['custom_rule_id'] in ('CSA-NET-001', 'CSA-NET-003'))} security groups rely on network position (an open CIDR) rather than identity. Session Manager, a bastion behind the Cloud Access Point, or an identity-aware proxy removes the need for open administrative ports.")
    A(f"- {sum(1 for f in open_f if f['custom_rule_id'] == 'CSA-NET-010')} API methods or function URLs have no authorization. Every request path should authenticate a caller (IAM, Cognito or a Lambda authorizer) before it reaches the integration.")
    A("- Templates cannot express account-level identity integration (SSO, MFA enforcement, CloudTrail organization trails). Those settings must be verified in the deployed account and are outside the scope of this static assessment.")
    A("")

    # ------------------------------------------------------------------ 8
    A("## 8. Remediation plan")
    A("")
    if remediated:
        A(f"### 8.1 Fixed in PR 2 ({len(remediated)} findings)")
        A("")
        A("Findings that the remediation branch no longer produces are marked `Remediated in PR` in the tracker. Templates changed:")
        A("")
        by_tpl: dict[str, list[dict]] = defaultdict(list)
        for f in remediated:
            by_tpl[f["template_path"]].append(f)
        A(table(["Template", "Findings closed", "Severities", "Rules"],
                [[t, len(fl), ", ".join(f"{k} {v}" for k, v in sorted(Counter(f["severity"] for f in fl).items())),
                  ", ".join(sorted({f["custom_rule_id"] or f["tool_rule_id"] for f in fl}))] for t, fl in sorted(by_tpl.items())]))
        A("")
    else:
        A("### 8.1 Planned for PR 2")
        A("")
        top10 = sorted(open_f, key=lambda f: f["risk_rank"])[:10]
        A(f"PR 2 fixes the ten highest-ranked open findings ({sum(f['severity'] == csa.CAT_I for f in top10)} CAT I, "
          f"{sum(f['severity'] == csa.CAT_II for f in top10)} CAT II; {len(cat1_open)} CAT I findings are open in total) and the CAT II findings on the same resources "
          "where the fix is safe without knowing the Government environment. Fixes planned, by finding:")
        A("")
        planned = Counter(f["title"] for f in top10)
        fix_for = {f["title"]: f["recommended_remediation"] for f in top10}
        for title, n in planned.most_common():
            A(f"- {title} ({n}): {fix_for[title]}")
        A("")
    A("### 8.2 Open for Government disposition")
    A("")
    A(f"- {sev[csa.CAT_I]} CAT I, {sev[csa.CAT_II]} CAT II and {sev[csa.CAT_III]} CAT III findings remain open. Sheet `POAM-Draft` lists every open CAT I and CAT II finding in POA&M layout with an owner role, milestones and a scheduled-completion placeholder.")
    ra = Counter(f"{f['title']} (`{f['custom_rule_id'] or f['tool_rule_id']}`, {f['severity']})" for f in risk_acc)
    A(f"- {len(risk_acc)} findings are recommended for risk acceptance: " + "; ".join(f"{n} × {k}" for k, n in ra.most_common())
      + ". Each carries a disposition note in the tracker. The system owner must confirm each acceptance and record it.")
    A("- Suggested schedule from Government acceptance of this report: CAT I 30 days, CAT II 90 days, CAT III 180 days, consistent with the target-date placeholders in the tracker.")
    A("")

    # ------------------------------------------------------------------ 9
    A("## 9. Decisions requiring Government action")
    A("")
    A("The following cannot be decided from the templates alone and were not guessed:")
    A("")
    A("- **Administrative CIDR ranges.** Remediated templates take the permitted management CIDR as a parameter with no open default. The Government must supply the Cloud Access Point or management network range at deployment.")
    A("- **KMS key ownership.** Encryption fixes use AWS-managed keys or a KMS key parameter. The Government must decide whether a customer-managed key with a documented rotation and key policy is required for each data classification (`CSA-KMS-001`, `CSA-ENC-002`, `CSA-ENC-010`).")
    A("- **Central logging destinations.** VPC Flow Logs, load balancer access logs, S3 access logs and API Gateway execution logs need a Government-owned log bucket or log group and retention period. The templates do not name one.")
    A("- **Public load balancers and bastions.** Internet-facing web tiers and bastion hosts keep their intent. The Government must decide, for each, whether it is approved through the Cloud Access Point and boundary architecture or whether the bastion is replaced with Session Manager.")
    if any(f["custom_rule_id"] == "CSA-MON-002" for f in open_f):
        A("- **Lambda network placement.** Functions flagged `CSA-MON-002` run outside a VPC although the stack contains VPC data resources. Placing them in a VPC changes connectivity and requires endpoint or NAT design decisions.")
    A("- **Risk acceptance.** The Government must accept or reject the CAT III findings recommended for risk acceptance and any finding it considers not applicable to a given workload; `--dispositions` records those decisions in the next run.")
    if not n_tf:
        A("- **Terraform.** None exists in this revision. The Government must state whether a Terraform module exists on another branch or repository so it can be brought into scope.")
    A("")

    # ------------------------------------------------------------------ 10
    A("## Appendix A. Control crosswalk (custom rule pack)")
    A("")
    A("One row per custom rule. Tool IDs are the Checkov and cfn_nag checks merged into the rule when they fire on the same resource. Hits are findings of all dispositions in this run. SRG area codes are expanded in table A.2.")
    A("")
    area_code = {text: key for key, text in csa.SRG_AREAS.items()}
    A("**A.1 Rule crosswalk**")
    A("")
    A(table(["Rule (default CAT, hits)", "Finding", "NIST 800-53 Rev. 5 / CIS v3.0", "SRG area; merged tool IDs"],
            [[f"{r['id']} ({r['default_severity']}, {r['hits']})", r["title"],
              f"{', '.join(r['nist'])} / CIS {r['cis_aws_v3_id'] or 'n/a'}",
              f"{area_code[r['dod_cloud_srg_area']]}; {', '.join(r['overlapping_tool_ids']) or 'no tool overlap'}"] for r in meta["custom_rules"]]))
    A("")
    A("**A.2 DoD Cloud Computing SRG area codes**")
    A("")
    A(table(["Code", "SRG topic area and Mission Owner SRG requirement"], [[k, v] for k, v in csa.SRG_AREAS.items()]))
    A("")
    A("## Appendix B. Tool-only findings by check")
    A("")
    A("Checkov, cfn_nag and cfn-lint results that did not merge into a custom rule, with the control mapping applied. The 30 most frequent checks are listed; the full set is in the tracker.")
    A("")
    tool_rows: dict[str, dict] = {}
    for f in findings:
        if f["custom_rule_id"]:
            continue
        key = f["tool_rule_id"].split(";")[0].strip()
        e = tool_rows.setdefault(key, {"n": 0, "sev": f["severity"], "nist": f["nist_controls"], "title": f["title"], "src": f["source"]})
        e["n"] += 1
    A(table(["Check (source, CAT, count)", "Finding", "NIST 800-53 Rev. 5"],
            [[f"{k} ({e['src']}, {e['sev']}, {e['n']})", e["title"][:110], ", ".join(e["nist"])]
             for k, e in sorted(tool_rows.items(), key=lambda kv: (-kv[1]["n"], kv[0]))[:30]]))
    A("")
    A("## Appendix C. References")
    A("")
    for title, url in REFERENCES:
        A(f"- {title} — [{url}]({url})")
    A("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", default="security-assessment/findings.json")
    ap.add_argument("--out", default="security-assessment/Cloud-Security-Assessment-Report.md")
    args = ap.parse_args(argv)
    data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    Path(args.out).write_text(build(data), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
