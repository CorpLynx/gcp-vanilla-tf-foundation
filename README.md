# gcp-vanilla-tf-foundation

A self-contained, plain-Terraform implementation of a GCP organization foundation targeting FedRAMP High compliance. Covers the same surface area as FAST stages 0–2 using only native `hashicorp/google` resources — no YAML factories, no FAST abstractions.

Target organization: `gigachadglobal.org` (ID: `1041701195417`)
State backend: Terraform Cloud / Enterprise

---

## Prerequisites

- **Terraform CLI >= 1.9** — [install guide](https://developer.hashicorp.com/terraform/install)
- **Terraform Cloud / Enterprise account** — workspace must exist before `terraform init`
- **GCP organization** — you must have org-level access
- **IaC Service Account** with the following roles at `organizations/1041701195417`:
  - `roles/resourcemanager.organizationAdmin`
  - `roles/resourcemanager.folderAdmin`
  - `roles/orgpolicy.policyAdmin`
  - `roles/iam.organizationRoleAdmin`
  - `roles/logging.admin`
  - `roles/assuredworkloads.admin`
  - `roles/cloudasset.owner`
  - `roles/accesscontextmanager.policyAdmin`
- **Application Default Credentials** configured locally with permission to impersonate the IaC SA:
  ```
  gcloud auth application-default login
  ```

---

## Required Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `org_id` | `string` | `"1041701195417"` | GCP organization numeric ID |
| `billing_account` | `string` | — | Billing account ID (e.g. `XXXXXX-XXXXXX-XXXXXX`) |
| `org_domain` | `string` | — | Organization domain (e.g. `gigachadglobal.org`) |
| `iac_sa_email` | `string` | — | IaC service account email used for provider impersonation |
| `admin_group_email` | `string` | — | Admin Google group email (e.g. `gcp-organization-admins@gigachadglobal.org`) |
| `tfc_organization` | `string` | — | Terraform Cloud organization name |
| `tfc_workspace` | `string` | — | Terraform Cloud workspace name |
| `log_bucket_name` | `string` | — | Destination log bucket resource name for org-level sinks |
| `primary_location` | `string` | `"us-east4"` | Primary GCP region — must start with `us-` (FedRAMP data residency) |

Create a `terraform.tfvars` file (do not commit secrets):

```hcl
billing_account   = "XXXXXX-XXXXXX-XXXXXX"
org_domain        = "gigachadglobal.org"
iac_sa_email      = "terraform@<project>.iam.gserviceaccount.com"
admin_group_email = "gcp-organization-admins@gigachadglobal.org"
tfc_organization  = "<your-tfc-org>"
tfc_workspace     = "<your-workspace>"
log_bucket_name   = "logging.googleapis.com/projects/<project>/locations/global/buckets/<bucket>"
```

---

## Backend Configuration

The `cloud {}` backend block in `versions.tf` requires the `organization` and `workspaces.name` values to be hardcoded (Terraform backend blocks do not support variable interpolation). Update `versions.tf` with your values, or pass them at init time:

```bash
terraform init \
  -backend-config="organization=<your-tfc-org>" \
  -backend-config="workspaces.name=<your-workspace>"
```

---

## Apply Order

Terraform's dependency graph enforces the correct order automatically. The logical sequence is:

1. **Custom roles** (`modules/custom-role`) — must exist before IAM bindings reference them
2. **Folder hierarchy** (`modules/folder`) — AW Root first, then FedRAMP High as child
3. **Assured Workload** — scoped to the FedRAMP High folder
4. **Org-level IAM** (`modules/iam`) — bindings at `organizations/1041701195417`
5. **Custom constraints** (`modules/org-policy`) — must exist before policies reference them
6. **Org policies** (`modules/org-policy`) — explicit `depends_on` to custom constraints
7. **Data access logging** (`google_organization_iam_audit_config`)
8. **Log sinks** (`google_logging_organization_sink`)

---

## Initialize and Apply

```bash
# 1. Initialize (downloads providers, configures TFC backend)
terraform init

# 2. Review the plan
terraform plan -out=tfplan

# 3. Apply
terraform apply tfplan
```

To destroy (note: FedRAMP High folder and Assured Workload have `prevent_destroy = true` and require manual lifecycle block removal before destruction):

```bash
terraform destroy
```

---

## Module Structure

```
gcp-vanilla-tf-foundation/
├── main.tf          # Provider config, module calls, direct resources
├── variables.tf     # All root input variables
├── outputs.tf       # folder_ids, custom_role_ids, org_policy_ids, audit_config_id
├── versions.tf      # required_version, required_providers, cloud backend
├── README.md
└── modules/
    ├── folder/      # google_folder resource
    ├── iam/         # google_organization_iam_binding / _member resources
    ├── org-policy/  # google_org_policy_custom_constraint + google_org_policy_policy
    └── custom-role/ # google_organization_iam_custom_role resource
```
