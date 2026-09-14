# Cloud Security Assessment artifacts

This directory holds the Cloud Security Assessment Report (CDRL A008 form: narrative report plus findings tracker) for the CloudFormation templates in this repository, treated as the infrastructure-as-code baseline for a set of Government cloud workloads.

## Artifacts

| File | Description |
|---|---|
| `Cloud-Security-Assessment-Report.md` | Narrative report: executive summary, scope and method, top 20 risk-ranked findings, findings by NIST control family, systemic patterns, secure-by-default automation, Zero Trust observations, remediation plan, decisions requiring Government action, control crosswalk appendix. Generated from `findings.json`; every number in it is derived from the data. |
| `Cloud-Security-Findings-Tracker.xlsx` | Findings tracker (openpyxl). Sheets: `Findings` (one row per finding, frozen header, autofilter, fill by severity), `Summary` (counts by severity, service directory and control family; scan date; commit SHA; before/after counts when a baseline is supplied), `Control-Coverage` (per NIST control: findings, open, remediated, templates with findings, templates assessed), `POAM-Draft` (one row per open CAT I / CAT II finding in POA&M layout), `Method` (tools, versions, rule pack, severity policy, known limits, Terraform applicability). |
| `findings.json` | Machine-readable source of both documents: `metadata` (scan date, commit, tools, custom rules, resource-type counts, template list), `summary`, `before_remediation` (when a baseline is supplied), `control_coverage`, and `findings` (the normalized finding schema). |

Every finding carries: finding ID, template path, service directory, resource logical ID and type, title, description, evidence (`file:line` plus snippet), DISA-style severity (CAT I / II / III) with justification, risk rank, NIST SP 800-53 Rev. 5 control IDs, CIS AWS Foundations Benchmark v3.0 recommendation ID where one exists, DoD Cloud Computing SRG area, tool and rule IDs (`CSA-*`, `CKV_*`, cfn_nag `W*/F*`, cfn-lint `E*`), recommended remediation, disposition, owner role, target-date placeholder and tags.

## Regenerate

Prerequisites: Python 3.10+, `pip install checkov cfn-lint pyyaml openpyxl`, and optionally `gem install cfn-nag` (the runner skips cfn_nag when it is not installed) and `rain` (used to package templates that contain `!Rain::` directives before linting, as `scripts/lint-single.sh` does).

```bash
# 1. Scan every template, run Checkov / cfn_nag / cfn-lint and the custom rule pack,
#    write findings.json and the XLSX tracker, print a console summary.
python3 scripts/cloud_security_assessment.py

# 2. Render the narrative report from findings.json.
python3 scripts/cloud_security_report.py
```

Useful options for `scripts/cloud_security_assessment.py`:

| Option | Purpose |
|---|---|
| `--baseline <findings.json>` | Compare with a previous run. Findings that no longer appear are carried forward with disposition `Remediated in PR` when every tool that produced them ran again on that template; if a tool was skipped, failed or could not process the template, the baseline disposition is kept and the note reads `Not re-evaluated`. `Summary` gains before/after severity counts. Used on the remediation branch. |
| `--dispositions <file.json>` | Apply Government dispositions: `{"<finding id>": {"disposition": "Risk acceptance recommended", "note": "..."}}`. Allowed values: `Open`, `Remediated in PR`, `Risk acceptance recommended`, `Not applicable`. |
| `--include-generated-json` | Assess generated JSON twins as independent templates (by default they are compared with their YAML source and only drift is reported). |
| `--skip-checkov`, `--skip-cfn-nag`, `--skip-cfn-lint` | Skip a tool. The `Method` sheet records what ran. |
| `--fail-on-incomplete` | Exit 2 when a scanner was skipped, failed, or left templates unprocessed; when a custom rule raised on a template (`metadata.custom_rule_failures`); when a file with a template extension is not well-formed JSON/YAML (`metadata.malformed_files`, assessed by no scanner); or when a generated JSON twin could not be compared with its source. A CI gate therefore cannot pass on an incomplete assessment. The console always prints the coverage gaps. |
| `--out-dir` | Output directory (default `security-assessment`). |

Terraform: the runner scans any `.tf` files it finds with Checkov (`--framework terraform`). No Terraform sources exist in this revision, so that part of the method is recorded as not applicable.

## Checking the workbook

```bash
python3 - <<'EOF'
import openpyxl
wb = openpyxl.load_workbook("security-assessment/Cloud-Security-Findings-Tracker.xlsx")
for ws in wb:
    print(ws.title, ws.max_row, "rows")
EOF
```

## Rendering the report to PDF

```bash
pandoc security-assessment/Cloud-Security-Assessment-Report.md -o Cloud-Security-Assessment-Report.pdf
# or
libreoffice --headless --convert-to pdf security-assessment/Cloud-Security-Assessment-Report.md
```
