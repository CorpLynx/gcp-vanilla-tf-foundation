#!/usr/bin/env bash
# grant-perms.sh — grant broad admin roles to the IaC SA for testing
# Run this after bootstrap.sh if you hit permission errors during terraform apply.

set -euo pipefail

ORG_ID="1041701195417"
BILLING_ACCOUNT="014F76-ED4E67-7CCCE1"
SA_EMAIL="tf-vanilla-rw@vanilla-bootstrap.iam.gserviceaccount.com"

echo "==> Granting org-level admin roles to ${SA_EMAIL}"

for ROLE in \
  roles/resourcemanager.organizationAdmin \
  roles/resourcemanager.folderAdmin \
  roles/resourcemanager.projectCreator \
  roles/resourcemanager.projectDeleter \
  roles/iam.organizationRoleAdmin \
  roles/iam.serviceAccountAdmin \
  roles/iam.workloadIdentityPoolAdmin \
  roles/orgpolicy.policyAdmin \
  roles/logging.admin \
  roles/monitoring.admin \
  roles/serviceusage.serviceUsageAdmin \
  roles/assuredworkloads.admin \
  roles/compute.admin \
  roles/storage.admin \
  roles/cloudkms.admin \
  roles/securitycenter.admin \
  roles/accesscontextmanager.policyAdmin \
  roles/cloudasset.owner \
  roles/essentialcontacts.admin \
  roles/networksecurity.admin \
  roles/billing.projectManager; do
  echo "    Granting ${ROLE}"
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --condition=None
done

echo "==> Granting billing account admin role"
gcloud billing accounts add-iam-policy-binding "${BILLING_ACCOUNT}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/billing.admin"

echo ""
echo "✓ Done. All roles granted to ${SA_EMAIL}"
