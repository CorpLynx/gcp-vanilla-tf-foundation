#!/usr/bin/env bash
# bootstrap.sh — one-time gcloud runbook to bootstrap the IaC project
# before the first `terraform apply`.
#
# What this does (emulating FAST stage 0 bootstrap):
#   1. Create the IaC seed project
#   2. Link billing account
#   3. Enable required APIs
#   4. Create the IaC service account (used by Terraform for impersonation)
#   5. Grant the IaC SA broad org-level permissions for testing
#   6. Create a WIF pool + GitHub OIDC provider
#   7. Grant the WIF pool permission to impersonate the IaC SA
#   8. Grant your user account permission to impersonate the IaC SA (for local runs)
#
# Prerequisites:
#   - gcloud auth login (as an org admin)
#   - gcloud auth application-default login
#   - Org admin role on the GCP organization

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
ORG_ID="1041701195417"
BILLING_ACCOUNT="014F76-ED4E67-7CCCE1"
PROJECT_ID="vanilla-bootstrap"
SA_NAME="tf-vanilla-rw"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
WIF_POOL_ID="default"
WIF_PROVIDER_ID="tfc-default"
TFC_ORGANIZATION="corplynx-lab"     # TODO: replace if different
TFC_WORKSPACE="gcp-vanilla"         # TODO: replace if different
LOCATION="global"
# ──────────────────────────────────────────────────────────────────────────────

echo "==> 1. Creating IaC seed project: ${PROJECT_ID}"
gcloud projects create "${PROJECT_ID}" \
  --organization="${ORG_ID}" \
  --name="IaC Core"

echo "==> 2. Linking billing account"
gcloud billing projects link "${PROJECT_ID}" \
  --billing-account="${BILLING_ACCOUNT}"

echo "==> 3. Enabling required APIs"
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  cloudbilling.googleapis.com \
  orgpolicy.googleapis.com \
  cloudasset.googleapis.com \
  serviceusage.googleapis.com \
  --project="${PROJECT_ID}"

echo "==> 4. Creating IaC service account"
gcloud iam service-accounts create "${SA_NAME}" \
  --display-name="IaC service account for org setup (read-write)" \
  --project="${PROJECT_ID}"

echo "==> 5. Granting IaC SA broad org-level permissions (testing only)"
# These are broad permissions suitable for testing — tighten for production
for ROLE in \
  roles/resourcemanager.organizationAdmin \
  roles/resourcemanager.folderAdmin \
  roles/resourcemanager.projectCreator \
  roles/resourcemanager.projectDeleter \
  roles/billing.projectManager \
  roles/iam.organizationRoleAdmin \
  roles/iam.serviceAccountAdmin \
  roles/orgpolicy.policyAdmin \
  roles/logging.admin \
  roles/serviceusage.serviceUsageAdmin \
  roles/assuredworkloads.admin \
  roles/compute.admin \
  roles/storage.admin \
  roles/cloudkms.admin \
  roles/monitoring.admin \
  roles/securitycenter.admin \
  roles/accesscontextmanager.policyAdmin \
  roles/cloudasset.owner \
  roles/essentialcontacts.admin \
  roles/networksecurity.admin; do
  echo "    Granting ${ROLE}"
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --condition=None
done

echo "==> 6. Creating WIF pool"
gcloud iam workload-identity-pools create "${WIF_POOL_ID}" \
  --location="${LOCATION}" \
  --display-name="Default CI/CD pool" \
  --project="${PROJECT_ID}"

echo "==> 7. Creating Terraform Cloud OIDC provider in WIF pool"
gcloud iam workload-identity-pools providers create-oidc "${WIF_PROVIDER_ID}" \
  --location="${LOCATION}" \
  --workload-identity-pool="${WIF_POOL_ID}" \
  --display-name="Terraform Cloud" \
  --issuer-uri="https://app.terraform.io" \
  --attribute-mapping="google.subject=assertion.sub,attribute.terraform_organization_name=assertion.terraform_organization_name,attribute.terraform_workspace_id=assertion.terraform_workspace_id,attribute.terraform_project_id=assertion.terraform_project_id" \
  --attribute-condition="attribute.terraform_organization_name=='${TFC_ORGANIZATION}'" \
  --project="${PROJECT_ID}"

# Get the full WIF pool resource name
WIF_POOL_NAME=$(gcloud iam workload-identity-pools describe "${WIF_POOL_ID}" \
  --location="${LOCATION}" \
  --project="${PROJECT_ID}" \
  --format="value(name)")

echo "==> 8. Granting TFC workspace permission to impersonate IaC SA (apply)"
# Scoped to the specific workspace ID — get this from TFC workspace settings
TFC_WORKSPACE_ID=$(curl -s \
  --header "Authorization: Bearer ${TFC_TOKEN:-REPLACE_WITH_TFC_TOKEN}" \
  --header "Content-Type: application/vnd.api+json" \
  "https://app.terraform.io/api/v2/organizations/${TFC_ORGANIZATION}/workspaces/${TFC_WORKSPACE}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['id'])")

echo "    TFC Workspace ID: ${TFC_WORKSPACE_ID}"

gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
  --project="${PROJECT_ID}" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/${WIF_POOL_NAME}/attribute.terraform_workspace_id/${TFC_WORKSPACE_ID}"

echo ""
echo "✓ Bootstrap complete."
echo ""
echo "  IaC Project:      ${PROJECT_ID}"
echo "  IaC SA:           ${SA_EMAIL}"
echo "  WIF Pool:         ${WIF_POOL_NAME}"
echo "  TFC Workspace ID: ${TFC_WORKSPACE_ID}"
echo ""
echo "  In TFC workspace settings, set these environment variables:"
echo "    TFC_GCP_PROVIDER_AUTH          = true"
echo "    TFC_GCP_RUN_SERVICE_ACCOUNT_EMAIL = ${SA_EMAIL}"
echo "    TFC_GCP_WORKLOAD_PROVIDER_NAME = ${WIF_POOL_NAME}/providers/${WIF_PROVIDER_ID}"
echo ""
echo "  Update terraform.tfvars:"
echo "    iac_sa_email   = \"${SA_EMAIL}\""
echo "    iac_project_id = \"${PROJECT_ID}\""
echo ""
echo "  Then run: terraform init && terraform apply"
