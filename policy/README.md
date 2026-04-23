# OPA/Conftest Policy Assertions

This directory contains [OPA](https://www.openpolicyagent.org/) policies for validating the `gcp-vanilla-tf-foundation` Terraform plan using [Conftest](https://www.conftest.dev/).

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.9
- [Conftest](https://www.conftest.dev/install/) ≥ 0.46

Install Conftest via Homebrew:

```bash
brew install conftest
```

Or download a binary from the [releases page](https://github.com/open-policy-agent/conftest/releases).

## Running the Policies

From the `gcp-vanilla-tf-foundation/` directory:

```bash
# 1. Initialise (if not already done)
terraform init

# 2. Generate a plan
terraform plan -out=plan.tfplan

# 3. Convert the plan to JSON
terraform show -json plan.tfplan > plan.json

# 4. Run Conftest assertions
conftest test plan.json --policy policy/
```

A passing run looks like:

```
PASS - plan.json - data.main.deny
```

Any failures are printed as `FAIL` messages with the specific assertion that was violated.

## What the Policies Assert

| # | Assertion | Rego rule |
|---|-----------|-----------|
| 1 | All 14 custom roles (`cloudkms_viewer`, `folder_viewer`, `logging_viewer`, `network_firewall_policies_admin`, `ngfw_enterprise_admin`, `ngfw_enterprise_viewer`, `organization_admin_viewer`, `organization_iam_admin`, `project_iam_viewer`, `service_account_viewer`, `service_networking_viewer`, `service_project_network_admin`, `storage_viewer`, `tag_viewer`) are present as `google_organization_iam_custom_role` resources | `missing_custom_roles` |
| 2 | `google_assured_workloads_workload` has `compliance_regime = "FEDRAMP_HIGH"` | `deny` (assertion 2) |
| 3 | `google_organization_iam_audit_config` targets `allServices` | `deny` (assertion 3) |
| 4 | All 3 log sinks (`audit-logs`, `iam`, `vpc-sc`) are present with the correct filter strings | `deny` (assertion 4) |
| 5 | No module call references a FAST module source path (`fast-modules` or `fabric-`) | `deny` (assertion 5) |
| 6 | `prevent_destroy = true` is set on the FedRAMP High `google_folder` and `google_assured_workloads_workload` | `deny` (assertion 6) |

## Plan JSON Structure Reference

The Terraform plan JSON (`terraform show -json`) used by these policies has the following relevant structure:

```
planned_values
  root_module
    resources[]              — resources declared directly in the root module
    child_modules[]
      resources[]            — resources inside child modules

configuration
  root_module
    resources[]              — root-level resource configurations (includes lifecycle blocks)
    module_calls             — map of module name → { source, module: { resources[] } }

resource_changes[]           — per-resource change details (actions, before/after values)
```

`prevent_destroy` is read from `configuration.root_module.resources[].lifecycle.prevent_destroy`
because it is a meta-argument and does not appear in `planned_values`.

## Files

| File | Description |
|------|-------------|
| `foundation.rego` | All policy assertions for the foundation plan |
| `README.md` | This file |
