# Cloud Security Assessment Report

Infrastructure-as-code baseline: CloudFormation templates in this repository at commit `ae3ddfdf161691fa1da37b8e3c256e4d59998761` (branch `devin/1789423490-cloud-security-assessment`), assessed 2026-09-15 00:05 UTC. The assessed templates were last changed in commit `a0f43bc6d20813052892546f445037cf84c75b54`; later commits on this branch (including the commit that adds these generated artifacts) do not change any assessed template. Prepared in the form of CDRL A008, Cloud Security Assessment Report, for the Government and the system owner.

## 1. Executive summary

This assessment treats the 160 CloudFormation templates in the repository as the infrastructure-as-code baseline for a set of Government cloud workloads. 3 open-source scanners (Checkov 3.3.17, cfn_nag 0.8.10, cfn-lint 1.56.3) and a custom rule pack of 55 checks were run against the 160 templates. Checkov did not process 7 template(s); cfn_nag did not process 12 template(s); cfn-lint did not process 2 template(s) (listed in the Method sheet); those templates are covered by the custom rule pack and the remaining scanners only. cfn-lint deliberately excluded 29 template(s) under the repository's lint conventions (scripts/lint-single.sh). Each result was normalized into one schema, mapped to NIST SP 800-53 Rev. 5 controls, the CIS AWS Foundations Benchmark v3.0 where a recommendation exists, and a DoD Cloud Computing SRG topic area, and assigned a DISA-style severity (CAT I, CAT II, CAT III) with a one-line justification.

The scan produced 1192 findings in 149 of 160 templates. 1174 findings are open, 0 are marked Remediated in PR, and 18 are recommended for risk acceptance.

| Severity | Open | Remediated in PR | Risk acceptance recommended | All findings |
|---|---|---|---|---|
| CAT I | 9 | 0 | 0 | 9 |
| CAT II | 371 | 0 | 0 | 371 |
| CAT III | 794 | 0 | 18 | 812 |
| Total | 1174 | 0 | 18 | 1192 |

Key results:

- 9 open CAT I findings: security group allows unrestricted ingress to administrative ports (4); security group allows unrestricted ingress on all ports and protocols (4); database storage is not encrypted at rest (1). They head the risk-ranked list in section 3 and are the first remediation targets.
- 371 open CAT II findings, dominated by: eC2 instance does not require IMDSv2 (HttpTokens: required) (60); eC2 Subnet should not have MapPublicIpOnLaunch set to true (cfn_nag W33) (26); security group admin-port ingress defaults to an unrestricted CIDR parameter (25); s3 bucket does not deny non-TLS (aws:SecureTransport=false) requests (25).
- 794 open CAT III findings, dominated by: iAM role has no permissions boundary (87); missing egress rule means all traffic is allowed outbound.  Make this explicit if it is desired configuration (cfn_nag F1000) (62); ensure every security groups rule has a description (checkov CKV_AWS_23) (59); iAM role uses inline policies (55).
- The dominant systemic pattern is the absence of secure defaults. The same weakness recurs across service directories because each template was written independently; section 5 quantifies this and section 6 recommends automation that prevents it.
- No Terraform sources exist in this revision, so the Terraform portion of the tasking is not applicable. The runner scans `.tf` files automatically when they are added.

## 2. Scope and method

### 2.1 Scope

- 160 CloudFormation templates (`.yaml`, `.yml`, `.json`, `.template` files with a `Resources` section) across 26 service directories with open findings. 17 candidate files were skipped because they are not CloudFormation templates (for example Lambda source, policy fragments, configuration files). Every file with a template extension was well-formed JSON or YAML.
- 138 JSON templates are generated twins of a YAML source in the same directory. YAML is the source of truth in this repository, so twins are not assessed separately (that would double every finding); each twin is compared with its source and drift is reported as finding `CSA-CFG-002`. Use `--include-generated-json` to assess twins as independent templates. Every twin was compared with its source.
- Terraform: 0 `.tf` files found. Not applicable to this revision.
- Static analysis only. No deployed-account evidence (AWS Config, Security Hub, CloudTrail) was available or used. Parameter values are evaluated from their template defaults.

### 2.2 Tools and versions

| Tool | Version | Status | Raw results | Note |
|---|---|---|---|---|
| checkov | 3.3.17 | ran | 478 | 7 template(s) could not be parsed by checkov and were covered by the custom rule pack only: CloudFormation/StackSets/common-resources.yaml, RainModules/bucket.yml, RainModules/static-site.yml, Solutions/GitLab/GitLabServ… |
| cfn_nag | 0.8.10 | ran | 518 | 12 template(s) could not be parsed by cfn_nag: CloudFormation/fn-foreach-ddb.yaml, CloudFormation/fn-foreach-s3-outputs.yaml, CloudFormation/MacrosExamples/Boto3/example.yaml, CloudFormation/MacrosExamples/ExecutionRoleB… |
| cfn-lint | cfn-lint 1.56.3 | ran | 14 | 56 warning/informational messages not treated as findings; 29 template(s) not linted per the repository lint convention (macro examples and Rain module fragments): CloudFormation/MacrosExamples/Boto3/example.yaml, CloudF… |

The custom rule pack (`scripts/cloud_security_assessment.py`, rule IDs `CSA-*`) adds 55 checks for conditions the scanners miss or that the Government baseline emphasizes: encryption at rest for every storage, database, queue, topic, stream and log resource; customer-managed versus AWS-managed KMS keys; TLS enforcement in transit; public exposure; logging and monitoring; IAM least privilege; IMDSv2; secrets handling; backup, retention and deletion protection.

### 2.3 Normalization, severity and ranking

- Every result carries file and line evidence, at least one NIST SP 800-53 Rev. 5 control, a DoD Cloud Computing SRG area, tool and rule IDs, a recommended remediation and a disposition. 693 findings come from the custom rule pack (of which many are corroborated by Checkov or cfn_nag on the same resource) and 499 are tool-only findings.
- CAT I (direct and immediate loss of confidentiality, integrity or availability) is assigned only when the custom rule pack verified the exact condition on the parsed template. Tool-only results that depend on pattern heuristics are capped at CAT II. A cfn_nag result that repeats an equivalent Checkov check on the same resource is merged so a weakness is counted once.
- Risk rank 1 is the highest risk. The score is the severity base (CAT I 300, CAT II 200, CAT III 100) plus modifiers for Internet exposure, credential material, data stores, corroborating tools and core service directories. Open findings rank ahead of closed ones.
- CIS AWS Foundations Benchmark v3.0.0 IDs are cited only where the AWS Security Hub CIS v3.0.0 control mapping confirms a matching recommendation. No IAM benchmark IDs are cited for template-level IAM findings because the benchmark's IAM section addresses account-level settings.

## 3. Risk-ranked findings (top 20)

The full list is in `Cloud-Security-Findings-Tracker.xlsx` (sheet `Findings`) and `findings.json`. Evidence is `template:line` in this repository at the commit above.

| # | Finding | Evidence (template:line, resource) and traceability |
|---|---|---|
| 1 | CAT I — CSA-NET-001-DB6129-0C0E: Security group allows unrestricted ingress to administrative ports | Solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml:242 `BastionSG`. NIST SC-7, SC-7(5), AC-17; CIS 5.2; CSA-NET-001; CKV_AWS_24; W9; W2 |
| 2 | CAT I — CSA-NET-001-96174D-0C0E: Security group allows unrestricted ingress to administrative ports | Solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml:264 `BastionSG`. NIST SC-7, SC-7(5), AC-17; CIS 5.2; CSA-NET-001; CKV_AWS_24; W9; W2 |
| 3 | CAT I — CSA-NET-001-EAB626-8C16: Security group allows unrestricted ingress to administrative ports | Solutions/EC2DomainJoin/EC2-Domain-Join.yaml:170 `InstanceSecurityGroup`. NIST SC-7, SC-7(5), AC-17; CIS 5.2; CSA-NET-001; CKV_AWS_25; W9; W2 |
| 4 | CAT I — CSA-NET-001-9E1C81-0C0E: Security group allows unrestricted ingress to administrative ports | EFS/efs_with_automount_to_ec2.yaml:313 `InstanceSecurityGroup`. NIST SC-7, SC-7(5), AC-17; CIS 5.2; CSA-NET-001; CKV_AWS_24; W9; W2 |
| 5 | CAT I — CSA-NET-003-F362F5-016A: Security group allows unrestricted ingress on all ports and protocols | ECS/EC2LaunchType/clusters/private-vpc.yaml:455 `PublicLoadBalancerSG`. NIST SC-7, SC-7(5), CM-7; CIS n/a; CSA-NET-003; W42; W9; W2 |
| 6 | CAT I — CSA-NET-003-BF62E5-016A: Security group allows unrestricted ingress on all ports and protocols | ECS/EC2LaunchType/clusters/public-vpc.yaml:323 `PublicLoadBalancerSG`. NIST SC-7, SC-7(5), CM-7; CIS n/a; CSA-NET-003; W42; W9; W2 |
| 7 | CAT I — CSA-NET-003-048FBF-016A: Security group allows unrestricted ingress on all ports and protocols | ECS/FargateLaunchType/clusters/private-vpc.yaml:293 `PublicLoadBalancerSG`. NIST SC-7, SC-7(5), CM-7; CIS n/a; CSA-NET-003; W42; W9; W2 |
| 8 | CAT I — CSA-NET-003-3A5EFB-016A: Security group allows unrestricted ingress on all ports and protocols | ECS/FargateLaunchType/clusters/public-vpc.yaml:159 `PublicLoadBalancerSG`. NIST SC-7, SC-7(5), CM-7; CIS n/a; CSA-NET-003; W42; W9; W2 |
| 9 | CAT I — CSA-ENC-003-C5F9F7: Database storage is not encrypted at rest | NeptuneDB/Neptune.yaml:311 `NeptuneDBCluster`. NIST SC-28, SC-28(1); CIS n/a; CSA-ENC-003; CKV_AWS_44 |
| 10 | CAT II — CSA-NET-007-5B39EA: S3 bucket does not block public access | CloudFormation/MacrosExamples/Count/test.yaml:16 `BucketToCopyA`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 11 | CAT II — CSA-NET-007-C22030: S3 bucket does not block public access | CloudFormation/MacrosExamples/Count/test.yaml:35 `BucketToCopyB`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 12 | CAT II — CSA-NET-007-9CA926: S3 bucket does not block public access | CloudFormation/MacrosExamples/Count/test.yaml:56 `BucketToCopyC`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 13 | CAT II — CSA-NET-007-C59284: S3 bucket does not block public access | CloudFormation/MacrosExamples/Count/test.yaml:75 `BucketToCopyD`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 14 | CAT II — CSA-NET-007-87C417: S3 bucket does not block public access | CloudFormation/MacrosExamples/DateFunctions/date_example.yaml:25 `S3Bucket`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 15 | CAT II — CSA-NET-007-71916B: S3 bucket does not block public access | CloudFormation/MacrosExamples/DatetimeNow/datetimenow_example.yaml:7 `S3Bucket`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 16 | CAT II — CSA-NET-007-432E1D: S3 bucket does not block public access | CloudFormation/MacrosExamples/Explode/test.yaml:15 `Bucket`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 17 | CAT II — CSA-NET-007-1C7354: S3 bucket does not block public access | CloudFormation/MacrosExamples/Explode/test.yaml:35 `NonExplodingBucket`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 18 | CAT II — CSA-NET-007-62E251: S3 bucket does not block public access | CloudFormation/MacrosExamples/PyPlate/python_example.yaml:15 `S3Bucket`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 19 | CAT II — CSA-NET-007-3A634D: S3 bucket does not block public access | CloudFormation/MacrosExamples/S3Objects/example.yaml:5 `Bucket`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |
| 20 | CAT II — CSA-NET-007-2648E7: S3 bucket does not block public access | CloudFormation/MacrosExamples/StackMetrics/example.yaml:5 `Bucket1`. NIST AC-3, SC-7, CM-6; CIS 2.1.4; CSA-NET-007; CKV_AWS_55; CKV_AWS_53; CKV_AWS_56; CKV_AWS_54 |

Evidence detail for the open CAT I findings:

- **CSA-NET-001-DB6129-0C0E** (rank 1) — `Solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml:242 — ports 22-22/tcp from 0.0.0.0/0`. Snippet: `- IpProtocol: tcp`. Direct and immediate loss of confidentiality, integrity or availability (DISA CAT I). Remediation: Replace the open CIDR with a parameterized Government CIDR (AllowedPattern that rejects /0), or remove the rule and use Systems Manager Session Manager / a bastion behind the CAP.
- **CSA-NET-001-96174D-0C0E** (rank 2) — `Solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml:264 — ports 22-22/tcp from 0.0.0.0/0`. Snippet: `- IpProtocol: tcp`. Direct and immediate loss of confidentiality, integrity or availability (DISA CAT I). Remediation: Replace the open CIDR with a parameterized Government CIDR (AllowedPattern that rejects /0), or remove the rule and use Systems Manager Session Manager / a bastion behind the CAP.
- **CSA-NET-001-EAB626-8C16** (rank 3) — `Solutions/EC2DomainJoin/EC2-Domain-Join.yaml:170 — ports 3389-3389/tcp from 0.0.0.0/0`. Snippet: `- IpProtocol: tcp`. Direct and immediate loss of confidentiality, integrity or availability (DISA CAT I). Remediation: Replace the open CIDR with a parameterized Government CIDR (AllowedPattern that rejects /0), or remove the rule and use Systems Manager Session Manager / a bastion behind the CAP.
- **CSA-NET-001-9E1C81-0C0E** (rank 4) — `EFS/efs_with_automount_to_ec2.yaml:313 — ports 22-22/tcp from 0.0.0.0/0`. Snippet: `- CidrIp: 0.0.0.0/0`. Direct and immediate loss of confidentiality, integrity or availability (DISA CAT I). Remediation: Replace the open CIDR with a parameterized Government CIDR (AllowedPattern that rejects /0), or remove the rule and use Systems Manager Session Manager / a bastion behind the CAP.
- **CSA-NET-003-F362F5-016A** (rank 5) — `ECS/EC2LaunchType/clusters/private-vpc.yaml:455 — IpProtocol=-1 ports None-None from 0.0.0.0/0`. Snippet: `- CidrIp: 0.0.0.0/0`. Direct and immediate loss of confidentiality, integrity or availability (DISA CAT I). Remediation: Restrict the rule to the required protocol and ports and to a known source security group or Government CIDR.
- **CSA-NET-003-BF62E5-016A** (rank 6) — `ECS/EC2LaunchType/clusters/public-vpc.yaml:323 — IpProtocol=-1 ports None-None from 0.0.0.0/0`. Snippet: `- CidrIp: 0.0.0.0/0`. Direct and immediate loss of confidentiality, integrity or availability (DISA CAT I). Remediation: Restrict the rule to the required protocol and ports and to a known source security group or Government CIDR.
- **CSA-NET-003-048FBF-016A** (rank 7) — `ECS/FargateLaunchType/clusters/private-vpc.yaml:293 — IpProtocol=-1 ports None-None from 0.0.0.0/0`. Snippet: `- CidrIp: 0.0.0.0/0`. Direct and immediate loss of confidentiality, integrity or availability (DISA CAT I). Remediation: Restrict the rule to the required protocol and ports and to a known source security group or Government CIDR.
- **CSA-NET-003-3A5EFB-016A** (rank 8) — `ECS/FargateLaunchType/clusters/public-vpc.yaml:159 — IpProtocol=-1 ports None-None from 0.0.0.0/0`. Snippet: `- CidrIp: 0.0.0.0/0`. Direct and immediate loss of confidentiality, integrity or availability (DISA CAT I). Remediation: Restrict the rule to the required protocol and ports and to a known source security group or Government CIDR.
- **CSA-ENC-003-C5F9F7** (rank 9) — `NeptuneDB/Neptune.yaml:311 — Properties.StorageEncrypted resolves to [False]`. Snippet: `StorageEncrypted: !Ref StorageEncrypted`. Direct and immediate loss of confidentiality, integrity or availability (DISA CAT I). Remediation: Set StorageEncrypted: true (Encrypted: true for Redshift) and supply KmsKeyId with a customer-managed key. Encryption is set at creation; existing instances need a snapshot-copy migration.

## 4. Findings by NIST SP 800-53 Rev. 5 control family

A finding that maps to controls in two families is counted in both. Counts are open findings.

| Control family | Open | CAT I | CAT II | CAT III | Most-cited controls (count) |
|---|---|---|---|---|---|
| System and Communications Protection | 493 | 9 | 253 | 231 | SC-7 (316), SC-28(1) (110), SC-8(1) (88), SC-8 (68), SC-28 (66), SC-7(5) (53) |
| Configuration Management | 473 | 4 | 86 | 383 | CM-6 (320), CM-5 (142), CM-2 (29), CM-3 (15), CM-7 (11) |
| Access Control | 398 | 4 | 195 | 199 | AC-6 (309), AC-6(1) (144), AC-3 (93), AC-17 (37), AC-4 (36) |
| Audit and Accountability | 136 | 0 | 20 | 116 | AU-12 (133), AU-2 (95), AU-11 (2), AU-9 (1) |
| Contingency Planning | 89 | 0 | 4 | 85 | CP-9 (89), CP-10 (34) |
| System and Information Integrity | 73 | 0 | 19 | 54 | SI-4 (70), SI-12 (2), SI-2 (1) |
| Identification and Authentication | 33 | 0 | 15 | 18 | IA-5 (31), IA-5(7) (3), IA-2 (2) |

Control coverage (open findings per control and templates with at least one finding for that control) is in sheet `Control-Coverage`. The controls with the most templates affected:

| Control | Title | Open findings | Templates with findings / assessed |
|---|---|---|---|
| CM-6 | Configuration Settings | 320 | 122 / 160 |
| AC-6 | Least Privilege | 309 | 101 / 160 |
| SC-7 | Boundary Protection | 316 | 92 / 160 |
| AU-12 | Audit Record Generation | 133 | 80 / 160 |
| CM-5 | Access Restrictions for Change | 142 | 78 / 160 |
| AU-2 | Event Logging | 95 | 64 / 160 |
| SC-28(1) | Protection of Information at Rest / Cryptographic Protection | 110 | 61 / 160 |
| AC-6(1) | Least Privilege / Authorize Access to Security Functions | 144 | 59 / 160 |
| SC-8(1) | Transmission Confidentiality and Integrity / Cryptographic Protection | 88 | 57 / 160 |
| SI-4 | System Monitoring | 70 | 50 / 160 |

## 5. Systemic patterns

The counts below compare open rule hits with the number of resources of the relevant type in the assessed templates. They show that the weaknesses are baseline defaults, not isolated mistakes.

| Pattern | Affected resources (open) | Share | Rule |
|---|---|---|---|
| S3 buckets without declared server-side encryption | 13 of 46 | 28% | CSA-ENC-001 |
| S3 buckets without an aws:SecureTransport deny policy | 25 of 46 | 54% | CSA-TLS-001 |
| S3 buckets without a Public Access Block | 13 of 46 | 28% | CSA-NET-007 |
| S3 buckets without server access logging | 39 of 46 | 85% | CSA-LOG-001 |
| EC2 instances, launch templates and launch configurations without IMDSv2 required | 60 of 60 | 100% | CSA-CFG-001 |
| EC2 volumes, instances, launch templates and launch configurations with unencrypted block storage | 15 of 61 | 25% | CSA-ENC-004 |
| Database clusters and instances without storage encryption | 1 of 8 | 12% | CSA-ENC-003 |
| VPCs without a flow log | 19 of 19 | 100% | CSA-LOG-002 |
| Load balancers without access logging | 19 of 20 | 95% | CSA-LOG-003 |
| Security groups with administrative ports open to the Internet (all severities) | 29 of 99 | 29% | CSA-NET-001 |
| IAM roles without a permissions boundary | 87 of 88 | 99% | CSA-IAM-007 |
| IAM roles with inline policies | 55 of 88 | 62% | CSA-IAM-006 |
| IAM principals and policies granting write actions on Resource * | 20 of 106 | 19% | CSA-IAM-003 |
| Stateful resources without deletion protection or a Retain policy | 51 of 62 | 82% | CSA-BKP-002 |
| Lambda functions without active tracing | 38 of 38 | 100% | CSA-MON-001 |

Other patterns: 15 generated JSON templates differ from their YAML source (`CSA-CFG-002`), so a reviewer reading the JSON may see a different security posture than the one deployed from YAML. 25 security groups expose administrative ports through a CIDR parameter whose default is `0.0.0.0/0`; the parameter exists but its default undoes it.

## 6. Recommended secure-by-default automation

- **Pre-commit gate.** Add `cfn-lint` and `checkov` (framework `cloudformation`, with this repository's `.cfnlintrc` and a Checkov config that fails on HIGH and CRITICAL) as pre-commit hooks so a template cannot be committed with an open CIDR on port 22, an unencrypted volume or a bucket without a Public Access Block.
- **CI policy-as-code.** Run `python3 scripts/cloud_security_assessment.py` in CI and fail the job when a CAT I finding is introduced (compare `findings.json` against the previous run with `--baseline`). Publish the tracker as a build artifact so the POA&M stays current without manual editing.
- **Reusable secure modules.** The repository already uses Rain modules (`RainModules/`). Extend them with hardened building blocks — an encrypted, logged, TLS-only S3 bucket; an IMDSv2-required launch template; a security group that takes a CIDR parameter with an `AllowedPattern` that rejects `/0`; an HTTPS listener with a TLS 1.2+ policy — and reference the module instead of repeating resource properties in each template.
- **Parameter constraints.** Every CIDR parameter should carry `AllowedPattern` and a non-open default (or no default). Every secret parameter should carry `NoEcho: true` or be replaced by a Secrets Manager dynamic reference.
- **Generated-file discipline.** Regenerate JSON twins from YAML in CI (`rain fmt` or the repository's packaging step) and fail when the checked-in twin drifts.
- **Account-level guardrails.** Enable default EBS encryption, S3 account-level Block Public Access and IMDSv2 defaults at the account or organization level so the template default no longer decides the outcome.

## 7. Zero Trust and identity observations

- 188 open IAM findings. Roles are created per template with inline policies and without permissions boundaries, and 22 policies allow write actions on `Resource: *`. In a Zero Trust model each workload identity should be scoped to the resources it owns and constrained by a permissions boundary set by the platform team.
- 60 compute resources do not require IMDSv2. Without `HttpTokens: required`, an SSRF or local file-read weakness on the instance can steal the role credentials. This is the single most common identity-related weakness in the baseline.
- 33 security groups rely on network position (an open CIDR) rather than identity. Session Manager, a bastion behind the Cloud Access Point, or an identity-aware proxy removes the need for open administrative ports.
- 2 API methods or function URLs have no authorization. Every request path should authenticate a caller (IAM, Cognito or a Lambda authorizer) before it reaches the integration.
- Templates cannot express account-level identity integration (SSO, MFA enforcement, CloudTrail organization trails). Those settings must be verified in the deployed account and are outside the scope of this static assessment.

## 8. Remediation plan

### 8.1 Planned for PR 2

PR 2 fixes the ten highest-ranked open findings (9 CAT I, 1 CAT II; 9 CAT I findings are open in total) and the CAT II findings on the same resources where the fix is safe without knowing the Government environment. Fixes planned, by finding:

- Security group allows unrestricted ingress to administrative ports (4): Replace the open CIDR with a parameterized Government CIDR (AllowedPattern that rejects /0), or remove the rule and use Systems Manager Session Manager / a bastion behind the CAP.
- Security group allows unrestricted ingress on all ports and protocols (4): Restrict the rule to the required protocol and ports and to a known source security group or Government CIDR.
- Database storage is not encrypted at rest (1): Set StorageEncrypted: true (Encrypted: true for Redshift) and supply KmsKeyId with a customer-managed key. Encryption is set at creation; existing instances need a snapshot-copy migration.
- S3 bucket does not block public access (1): Add PublicAccessBlockConfiguration with BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls and RestrictPublicBuckets all true.

### 8.2 Open for Government disposition

- 9 CAT I, 371 CAT II and 794 CAT III findings remain open. Sheet `POAM-Draft` lists every open CAT I and CAT II finding in POA&M layout with an owner role, milestones and a scheduled-completion placeholder.
- 18 findings are recommended for risk acceptance: 18 × Security group allows unrestricted ingress on an application port (`CSA-NET-004`, CAT III). Each carries a disposition note in the tracker. The system owner must confirm each acceptance and record it.
- Suggested schedule from Government acceptance of this report: CAT I 30 days, CAT II 90 days, CAT III 180 days, consistent with the target-date placeholders in the tracker.

## 9. Decisions requiring Government action

The following cannot be decided from the templates alone and were not guessed:

- **Administrative CIDR ranges.** Remediated templates take the permitted management CIDR as a parameter with no open default. The Government must supply the Cloud Access Point or management network range at deployment.
- **KMS key ownership.** Encryption fixes use AWS-managed keys or a KMS key parameter. The Government must decide whether a customer-managed key with a documented rotation and key policy is required for each data classification (`CSA-KMS-001`, `CSA-ENC-002`, `CSA-ENC-010`).
- **Central logging destinations.** VPC Flow Logs, load balancer access logs, S3 access logs and API Gateway execution logs need a Government-owned log bucket or log group and retention period. The templates do not name one.
- **Public load balancers and bastions.** Internet-facing web tiers and bastion hosts keep their intent. The Government must decide, for each, whether it is approved through the Cloud Access Point and boundary architecture or whether the bastion is replaced with Session Manager.
- **Lambda network placement.** Functions flagged `CSA-MON-002` run outside a VPC although the stack contains VPC data resources. Placing them in a VPC changes connectivity and requires endpoint or NAT design decisions.
- **Risk acceptance.** The Government must accept or reject the CAT III findings recommended for risk acceptance and any finding it considers not applicable to a given workload; `--dispositions` records those decisions in the next run.
- **Terraform.** None exists in this revision. The Government must state whether a Terraform module exists on another branch or repository so it can be brought into scope.

## Appendix A. Control crosswalk (custom rule pack)

One row per custom rule. Tool IDs are the Checkov and cfn_nag checks merged into the rule when they fire on the same resource. Hits are findings of all dispositions in this run. SRG area codes are expanded in table A.2.

**A.1 Rule crosswalk**

| Rule (default CAT, hits) | Finding | NIST 800-53 Rev. 5 / CIS v3.0 | SRG area; merged tool IDs |
|---|---|---|---|
| CSA-ENC-001 (CAT II, 13) | S3 bucket does not declare server-side encryption | SC-28, SC-28(1) / CIS n/a | encryption_rest; CKV_AWS_19, W41 |
| CSA-ENC-002 (CAT III, 29) | S3 bucket encryption does not use a customer-managed KMS key | SC-28(1), SC-12 / CIS n/a | encryption_rest; CKV_AWS_145 |
| CSA-ENC-003 (CAT I, 1) | Database storage is not encrypted at rest | SC-28, SC-28(1) / CIS 2.3.1 | encryption_rest; CKV_AWS_16, CKV_AWS_44, CKV_AWS_64, CKV_AWS_74, CKV_AWS_96, F26, F27, F28 |
| CSA-ENC-004 (CAT II, 15) | EBS volume is not encrypted | SC-28, SC-28(1) / CIS 2.2.1 | encryption_rest; CKV_AWS_189, CKV_AWS_3, CKV_AWS_8, F1 |
| CSA-ENC-005 (CAT II, 0) | EFS file system is not encrypted at rest | SC-28, SC-28(1) / CIS 2.4.1 | encryption_rest; CKV_AWS_184, CKV_AWS_42 |
| CSA-ENC-006 (CAT III, 8) | SQS queue does not declare server-side encryption | SC-28, SC-28(1) / CIS n/a | encryption_rest; CKV_AWS_27, W48 |
| CSA-ENC-007 (CAT II, 3) | SNS topic is not encrypted at rest | SC-28, SC-28(1) / CIS n/a | encryption_rest; CKV_AWS_26, W47 |
| CSA-ENC-008 (CAT III, 1) | CloudWatch log group is not encrypted with a customer-managed key | SC-28(1), AU-9 / CIS n/a | encryption_rest; CKV_AWS_158, W84 |
| CSA-ENC-009 (CAT II, 0) | Streaming resource is not encrypted at rest | SC-28, SC-28(1) / CIS n/a | encryption_rest; CKV_AWS_240, CKV_AWS_241, CKV_AWS_43 |
| CSA-ENC-010 (CAT III, 7) | DynamoDB table does not use a customer-managed KMS key | SC-28(1), SC-12 / CIS n/a | encryption_rest; CKV_AWS_119, W74 |
| CSA-ENC-011 (CAT II, 0) | CloudTrail trail logs are not encrypted with KMS | AU-9, SC-28(1) / CIS 3.5 | encryption_rest; CKV_AWS_35 |
| CSA-ENC-012 (CAT II, 1) | Cache or search domain is not encrypted at rest | SC-28, SC-28(1) / CIS n/a | encryption_rest; CKV_AWS_247, CKV_AWS_29, CKV_AWS_31, CKV_AWS_5, F25, F33 |
| CSA-KMS-001 (CAT III, 7) | Encrypted resource relies on an AWS-managed key instead of a customer-managed key | SC-12, SC-28(1) / CIS n/a | encryption_rest; no tool overlap |
| CSA-KMS-002 (CAT III, 2) | KMS key does not enable automatic rotation | SC-12 / CIS 3.6 | encryption_rest; CKV_AWS_7 |
| CSA-TLS-001 (CAT II, 25) | S3 bucket does not deny non-TLS (aws:SecureTransport=false) requests | SC-8, SC-8(1) / CIS 2.1.1 | encryption_transit; no tool overlap |
| CSA-TLS-002 (CAT II, 15) | Load balancer listener accepts clear-text traffic | SC-8, SC-8(1) / CIS n/a | encryption_transit; CKV_AWS_2, W56 |
| CSA-TLS-003 (CAT II, 4) | HTTPS listener does not enforce a TLS 1.2+ security policy | SC-8(1), SC-13 / CIS n/a | encryption_transit; CKV_AWS_103, W55 |
| CSA-TLS-004 (CAT II, 5) | RDS database does not enforce TLS connections (rds.force_ssl / require_secure_transport) | SC-8, SC-8(1) / CIS n/a | encryption_transit; no tool overlap |
| CSA-TLS-005 (CAT II, 9) | Edge endpoint allows TLS below 1.2 or clear-text viewers | SC-8(1), SC-13 / CIS n/a | encryption_transit; CKV_AWS_174, CKV_AWS_228, CKV_AWS_30, CKV_AWS_34, CKV_AWS_6, CKV_AWS_83, W70 |
| CSA-NET-001 (CAT I, 29) | Security group allows unrestricted ingress to administrative ports | SC-7, SC-7(5), AC-17 / CIS 5.2 | boundary; CKV_AWS_24, CKV_AWS_25, W2, W40, W9 |
| CSA-NET-002 (CAT I, 1) | Security group allows unrestricted ingress to database or cache ports | SC-7, SC-7(5), AC-3 / CIS n/a | boundary; W2, W9 |
| CSA-NET-003 (CAT I, 4) | Security group allows unrestricted ingress on all ports and protocols | SC-7, SC-7(5), CM-7 / CIS n/a | boundary; W2, W40, W42, W9 |
| CSA-NET-004 (CAT III, 20) | Security group allows unrestricted ingress on an application port | SC-7, SC-7(5) / CIS n/a | boundary; CKV_AWS_260, W2, W9 |
| CSA-NET-005 (CAT I, 0) | Database is publicly accessible | SC-7, AC-3 / CIS 2.3.3 | boundary; CKV_AWS_17, CKV_AWS_87, F22 |
| CSA-NET-006 (CAT I, 0) | S3 bucket grants public or anonymous access | AC-3, SC-7, AC-6 / CIS n/a | boundary; CKV_AWS_20, CKV_AWS_57, CKV_AWS_70, F14, F15, F16 |
| CSA-NET-007 (CAT II, 13) | S3 bucket does not block public access | AC-3, SC-7, CM-6 / CIS 2.1.4 | boundary; CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56 |
| CSA-NET-008 (CAT II, 1) | EKS cluster API endpoint is reachable from the Internet | SC-7, AC-17 / CIS n/a | boundary; CKV_AWS_38, CKV_AWS_39 |
| CSA-NET-009 (CAT II, 2) | Data-tier subnet group uses public subnets | SC-7, AC-4 / CIS n/a | boundary; no tool overlap |
| CSA-NET-010 (CAT II, 2) | API method or function URL has no authorization | AC-3, IA-2, SC-7 / CIS n/a | boundary; CKV_AWS_258, CKV_AWS_309, CKV_AWS_59 |
| CSA-LOG-001 (CAT III, 39) | S3 bucket has no server access logging | AU-2, AU-12 / CIS n/a | logging; CKV_AWS_18, W35 |
| CSA-LOG-002 (CAT II, 19) | VPC has no flow log | AU-2, AU-12, SI-4 / CIS 3.7 | logging; W60 |
| CSA-LOG-003 (CAT III, 19) | Load balancer access logging is disabled | AU-2, AU-12 / CIS n/a | logging; CKV_AWS_91, CKV_AWS_92, W26, W52 |
| CSA-LOG-004 (CAT III, 2) | API Gateway stage has no execution or access logging | AU-2, AU-12 / CIS n/a | logging; CKV_AWS_76, CKV_AWS_95 |
| CSA-LOG-005 (CAT III, 5) | RDS database does not export logs to CloudWatch Logs | AU-2, AU-12 / CIS n/a | logging; CKV_AWS_129 |
| CSA-LOG-006 (CAT II, 1) | EKS control-plane logging is incomplete | AU-2, AU-12 / CIS n/a | logging; CKV_AWS_37 |
| CSA-LOG-007 (CAT III, 0) | CloudTrail trail is not multi-Region or lacks log file validation | AU-2, AU-9, AU-12 / CIS 3.1 | logging; CKV_AWS_36, CKV_AWS_67 |
| CSA-LOG-008 (CAT III, 2) | CloudWatch log group has no retention period | AU-11, SI-12 / CIS n/a | logging; CKV_AWS_66, W86 |
| CSA-MON-001 (CAT III, 38) | Lambda function has no active tracing | SI-4, AU-12 / CIS n/a | monitoring; CKV_AWS_50 |
| CSA-MON-002 (CAT III, 9) | Lambda function is not attached to a VPC although the stack contains VPC data resources | SC-7, AC-4 / CIS n/a | boundary; CKV_AWS_117, W89 |
| CSA-IAM-001 (CAT I, 0) | IAM policy grants full administrative privileges (Action * on Resource *) | AC-6, AC-6(1), AC-3 / CIS n/a | iam; CKV_AWS_1, CKV_AWS_107, CKV_AWS_108, CKV_AWS_109, CKV_AWS_110, CKV_AWS_111, CKV_AWS_286, CKV_AWS_287, CKV_AWS_288, CKV_AWS_289, CKV_AWS_290, F2, F3, F38, F39, F4, F40, F41, F5 |
| CSA-IAM-002 (CAT II, 24) | IAM policy uses service-level wildcard actions | AC-6, AC-6(1) / CIS n/a | iam; CKV_AWS_107, CKV_AWS_108, CKV_AWS_109, CKV_AWS_110, CKV_AWS_111, F2, F3, F4, F5, W11, W12, W13 |
| CSA-IAM-003 (CAT II, 22) | IAM policy allows write actions on Resource * | AC-6, AC-3 / CIS n/a | iam; CKV_AWS_355, CKV_AWS_356, F39, F4, F5, W11, W12, W13 |
| CSA-IAM-004 (CAT II, 0) | IAM policy allows iam:PassRole on Resource * | AC-6, AC-6(1), AC-3 / CIS n/a | iam; CKV_AWS_110 |
| CSA-IAM-005 (CAT II, 0) | IAM user or group carries inline policies or long-lived credentials | AC-2, AC-6, IA-5 / CIS n/a | iam; CKV_AWS_273, CKV_AWS_274, CKV_AWS_40, F10, F11, F12 |
| CSA-IAM-006 (CAT III, 55) | IAM role uses inline policies | AC-6, CM-6 / CIS n/a | iam; no tool overlap |
| CSA-IAM-007 (CAT III, 87) | IAM role has no permissions boundary | AC-6, AC-6(1), CM-5 / CIS n/a | iam; no tool overlap |
| CSA-IAM-008 (CAT I, 0) | Trust or resource policy grants access to Principal * | AC-3, AC-6, SC-7 / CIS n/a | iam; CKV_AWS_33, CKV_AWS_51, CKV_AWS_60, F13, F18, F21, F76 |
| CSA-CFG-001 (CAT II, 60) | EC2 instance does not require IMDSv2 (HttpTokens: required) | CM-6, AC-6, SC-7 / CIS 5.6 | config; CKV_AWS_341, CKV_AWS_79 |
| CSA-SEC-001 (CAT I, 0) | Secret parameter is not marked NoEcho | IA-5, IA-5(7), SC-28 / CIS n/a | credentials; no tool overlap |
| CSA-SEC-002 (CAT II, 0) | Secret parameter carries a default value | IA-5, IA-5(7) / CIS n/a | credentials; no tool overlap |
| CSA-SEC-003 (CAT I, 0) | Credential appears to be hardcoded in the template | IA-5, IA-5(7) / CIS n/a | credentials; CKV_AWS_41, CKV_AWS_45, CKV_AWS_46, CKV_SECRET_2, CKV_SECRET_6 |
| CSA-SEC-004 (CAT III, 0) | Database master password is supplied as a template parameter instead of Secrets Manager | IA-5, IA-5(7) / CIS n/a | credentials; no tool overlap |
| CSA-BKP-001 (CAT III, 28) | Stateful resource has no backup or point-in-time recovery configuration | CP-9, CP-10 / CIS n/a | recovery; CKV_AWS_133, CKV_AWS_139, CKV_AWS_21, CKV_AWS_28 |
| CSA-BKP-002 (CAT III, 51) | Stateful resource lacks deletion protection or a Retain deletion policy | CP-9, CM-5 / CIS n/a | recovery; CKV_AWS_139, CKV_AWS_293, F80 |
| CSA-CFG-002 (CAT III, 15) | Generated JSON template is out of sync with its YAML source | CM-2, CM-3, CM-6 / CIS n/a | validity; no tool overlap |

**A.2 DoD Cloud Computing SRG area codes**

| Code | SRG topic area and Mission Owner SRG requirement |
|---|---|
| encryption_rest | Security Requirements — DoD Policy Regarding Security Controls (FedRAMP+ SC-28); Mission Owner SRG SRG-OS-000404-CLD-002720 (encrypt DoD files in cloud storage) |
| encryption_transit | Security Requirements — DoD Policy Regarding Security Controls (FedRAMP+ SC-8/SC-13, FIPS 140 validated cryptography) |
| boundary | Architecture — Mission Owner network boundary protection (CAP/VDSS); Mission Owner SRG SRG-OS-000480-CLD-000030 (restrict inbound/outbound traffic flow) |
| logging | Computer Network Defense and Incident Response — Continuous Monitoring; Mission Owner SRG SRG-OS-000342-CLD-000020 (centralized logging) |
| monitoring | Computer Network Defense and Incident Response — Continuous Monitoring; Mission Owner SRG SRG-NET-000383-CLD-000200 (IDPS / traffic monitoring) |
| iam | Identification, Authentication and Access Control; Mission Owner SRG SRG-OS-000001-CLD-000010 (privileged accounts configured for least privilege) |
| config | Security Requirements — Configuration management (CM-6/CM-7); Mission Owner SRG SRG-OS-000096-CLD-000150 (restrict functions, ports, protocols, services) |
| recovery | Data Recovery and Destruction (CP-9 backup and recovery of Mission Owner data) |
| credentials | Identification, Authentication and Access Control — authenticator management (IA-5) |
| validity | Security Requirements — Configuration management (CM-2/CM-6 baseline configuration) |

## Appendix B. Tool-only findings by check

Checkov, cfn_nag and cfn-lint results that did not merge into a custom rule, with the control mapping applied. The 30 most frequent checks are listed; the full set is in the tracker.

| Check (source, CAT, count) | Finding | NIST 800-53 Rev. 5 |
|---|---|---|
| F1000 (cfn_nag, CAT III, 62) | Missing egress rule means all traffic is allowed outbound.  Make this explicit if it is desired configuration  | SC-7 |
| CKV_AWS_23 (checkov+cfn_nag, CAT III, 59) | Ensure every security groups rule has a description (checkov CKV_AWS_23) | SC-7 |
| CKV_AWS_115 (checkov, CAT III, 38) | Ensure that AWS Lambda function is configured for function-level concurrent execution limit (checkov CKV_AWS_1 | CM-6 |
| CKV_AWS_116 (checkov, CAT III, 38) | Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) (checkov CKV_AWS_116) | CM-6 |
| W92 (cfn_nag, CAT III, 38) | Lambda functions should define ReservedConcurrentExecutions to reserve simultaneous executions (cfn_nag W92) | CM-6 |
| W33 (cfn_nag, CAT II, 26) | EC2 Subnet should not have MapPublicIpOnLaunch set to true (cfn_nag W33) | SC-7 |
| CKV_AWS_117 (checkov+cfn_nag, CAT III, 25) | Ensure that AWS Lambda function is configured inside a VPC (checkov CKV_AWS_117) | SC-7, AC-4 |
| W28 (cfn_nag, CAT III, 22) | Resource found with an explicit name, this disallows updates that require replacement of this resource (cfn_na | CM-6 |
| CKV_AWS_111 (checkov, CAT II, 19) | Ensure IAM policies does not allow write access without constraints (checkov CKV_AWS_111) | AC-6, AC-6(1), AC-3 |
| W51 (cfn_nag, CAT III, 17) | S3 bucket should likely have a bucket policy (cfn_nag W51) | AC-6, AC-3, IA-5 |
| CKV_AWS_173 (checkov, CAT III, 10) | Check encryption settings for Lambda environment variable (checkov CKV_AWS_173) | SC-28, SC-28(1), SC-8, SC-8(1) |
| CKV_AWS_131 (checkov, CAT III, 9) | Ensure that ALB drops HTTP headers (checkov CKV_AWS_131) | CM-6 |
| CKV_AWS_103 (checkov, CAT II, 7) | Ensure that Load Balancer Listener is using at least TLS v1.2 (checkov CKV_AWS_103) | SC-8(1), SC-13 |
| W42 (cfn_nag, CAT II, 7) | Security Groups ingress with an ipProtocol of -1 found  (cfn_nag W42) | SC-7, SC-7(5), CM-7 |
| CKV_AWS_109 (checkov, CAT II, 6) | Ensure IAM policies does not allow permissions management without constraints (checkov CKV_AWS_109) | AC-6, AC-6(1), AC-3 |
| CKV_AWS_118 (checkov, CAT III, 6) | Ensure that enhanced monitoring is enabled for Amazon RDS instances (checkov CKV_AWS_118) | SI-4 |
| W11 (cfn_nag, CAT II, 6) | IAM role should not allow * resource on its permissions policy (cfn_nag W11) | AC-6, AC-6(1) |
| CKV_AWS_157 (checkov, CAT III, 5) | Ensure that RDS instances have Multi-AZ enabled (checkov CKV_AWS_157) | CP-9, CP-10 |
| CKV_AWS_65 (checkov, CAT III, 5) | Ensure container insights are enabled on ECS cluster (checkov CKV_AWS_65) | SI-4 |
| CKV_AWS_68 (checkov, CAT III, 5) | CloudFront Distribution should have WAF enabled (checkov CKV_AWS_68) | CM-6 |
| CKV_AWS_364 (checkov, CAT II, 4) | Ensure that AWS Lambda function permissions delegated to AWS services are limited by SourceArn or SourceAccoun | AC-6, AC-3, IA-5 |
| CKV_AWS_86 (checkov+cfn_nag, CAT III, 4) | Ensure CloudFront Distribution has Access Logging enabled (checkov CKV_AWS_86) | AU-2, AU-12 |
| E3710 (cfn-lint, CAT III, 4) | Template does not pass cfn-lint (E3710) | CM-2, CM-6 |
| F80 (cfn_nag, CAT II, 4) | RDS instance should have deletion protection enabled (cfn_nag F80) | CP-9, CM-5 |
| CKV_AWS_46 (checkov, CAT II, 3) | Ensure no hard-coded secrets exist in EC2 user data (checkov CKV_AWS_46) | IA-5, IA-5(7) |
| W40 (cfn_nag, CAT III, 3) | Security Groups egress with an IpProtocol of -1 found (cfn_nag W40) | SC-7, SC-7(5), AC-17 |
| W5 (cfn_nag, CAT III, 3) | Security Groups found with cidr open to world on egress (cfn_nag W5) | SC-7, SC-7(5) |
| W58 (cfn_nag, CAT III, 3) | Lambda functions require permission to write CloudWatch Logs (cfn_nag W58) | AU-2, AU-12 |
| CKV_AWS_120 (checkov, CAT III, 2) | Ensure API Gateway caching is enabled (checkov CKV_AWS_120) | CM-6 |
| CKV_AWS_123 (checkov, CAT II, 2) | Ensure that VPC Endpoint Service is configured for Manual Acceptance (checkov CKV_AWS_123) | SC-7 |

## Appendix C. References

- NIST SP 800-53 Rev. 5 (with update 1), Security and Privacy Controls for Information Systems and Organizations — [https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- CIS Amazon Web Services Foundations Benchmark (v3.0.0 recommendation IDs are used in this report) — [https://www.cisecurity.org/benchmark/amazon_web_services](https://www.cisecurity.org/benchmark/amazon_web_services)
- AWS Security Hub — CIS AWS Foundations Benchmark controls (source of the v3.0.0 recommendation-to-control mapping) — [https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- DoD Cloud Computing Security Requirements Guide and Cloud Computing Mission Owner SRG (DISA Cyber Exchange, DCCS documents) — [https://public.cyber.mil/dccs/dccs-documents/](https://public.cyber.mil/dccs/dccs-documents/)
- Checkov — [https://github.com/bridgecrewio/checkov](https://github.com/bridgecrewio/checkov)
- cfn_nag — [https://github.com/stelligent/cfn_nag](https://github.com/stelligent/cfn_nag)
- cfn-lint — [https://github.com/aws-cloudformation/cfn-lint](https://github.com/aws-cloudformation/cfn-lint)
- Rain (CloudFormation packaging and module tool used by this repository) — [https://github.com/aws-cloudformation/rain](https://github.com/aws-cloudformation/rain)
