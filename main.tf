provider "google" {
  impersonate_service_account = var.iac_sa_email
}

provider "google-beta" {
  impersonate_service_account = var.iac_sa_email
}

# ---------------------------------------------------------------------------
# Folder hierarchy
# ---------------------------------------------------------------------------

module "folder_aw_root" {
  source = "./modules/folder"

  name   = "AW Root"
  parent = "organizations/${var.org_id}"
}

module "folder_fedramp_high" {
  source = "./modules/folder"

  name   = "FedRAMP High"
  parent = module.folder_aw_root.id
}

module "folder_network" {
  source = "./modules/folder"

  name   = "Network"
  parent = module.folder_fedramp_high.id
}

module "folder_security" {
  source = "./modules/folder"

  name   = "Security"
  parent = module.folder_fedramp_high.id
}

module "folder_core" {
  source = "./modules/folder"

  name   = "Core"
  parent = module.folder_fedramp_high.id
}

module "folder_workloads" {
  source = "./modules/folder"

  name   = "Workloads"
  parent = module.folder_fedramp_high.id
}

module "folder_shared_services" {
  source = "./modules/folder"

  name   = "Shared Services"
  parent = module.folder_fedramp_high.id
}

module "folder_workload_a" {
  source = "./modules/folder"

  name   = "workload-a"
  parent = module.folder_workloads.id
}

module "folder_workload_b" {
  source = "./modules/folder"

  name   = "workload-b"
  parent = module.folder_workloads.id
}

# ---------------------------------------------------------------------------
# Core projects
# ---------------------------------------------------------------------------

module "project_iac_core" {
  source = "./modules/project"

  name            = "IaC Core"
  project_id      = "iac-core-0"
  folder_id       = module.folder_core.id
  billing_account = var.billing_account
  labels = {
    env        = "core"
    managed-by = "terraform"
  }
}

module "project_billing_core" {
  source = "./modules/project"

  name            = "Billing Core"
  project_id      = "billing-core-0"
  folder_id       = module.folder_core.id
  billing_account = var.billing_account
  labels = {
    env        = "core"
    managed-by = "terraform"
  }
}

module "project_logging_core" {
  source = "./modules/project"

  name            = "Logging Core"
  project_id      = "logging-core-0"
  folder_id       = module.folder_core.id
  billing_account = var.billing_account
  labels = {
    env        = "core"
    managed-by = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Assured Workload — FedRAMP High boundary
# ---------------------------------------------------------------------------

resource "google_assured_workloads_workload" "fedramp_high" {
  compliance_regime               = "FEDRAMP_HIGH"
  display_name                    = "FedRAMP High Boundary"
  location                        = var.primary_location
  organization                    = var.org_id
  violation_notifications_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Custom IAM roles
# ---------------------------------------------------------------------------

module "custom_role_cloudkms_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "cloudkms_viewer"
  title       = "Cloud KMS Viewer"
  description = "Descoped viewer for Cloud KMS resources"
  permissions = [
    "cloudkms.autokeyConfigs.get",
    "cloudkms.cryptoKeyVersions.get",
    "cloudkms.cryptoKeyVersions.list",
    "cloudkms.cryptoKeys.get",
    "cloudkms.cryptoKeys.getIamPolicy",
    "cloudkms.cryptoKeys.list",
    "cloudkms.ekmConfigs.get",
    "cloudkms.ekmConfigs.getIamPolicy",
    "cloudkms.ekmConnections.get",
    "cloudkms.ekmConnections.getIamPolicy",
    "cloudkms.ekmConnections.list",
    "cloudkms.importJobs.get",
    "cloudkms.importJobs.getIamPolicy",
    "cloudkms.importJobs.list",
    "cloudkms.kajPolicyConfigs.get",
    "cloudkms.keyHandles.get",
    "cloudkms.keyHandles.list",
    "cloudkms.keyRings.get",
    "cloudkms.keyRings.getIamPolicy",
    "cloudkms.keyRings.list",
    "cloudkms.locations.get",
    "cloudkms.locations.list",
    "cloudkms.operations.get",
    "cloudkms.singleTenantHsmInstanceProposals.get",
    "cloudkms.singleTenantHsmInstanceProposals.list",
    "cloudkms.singleTenantHsmInstances.get",
    "cloudkms.singleTenantHsmInstances.list",
  ]
}

module "custom_role_folder_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "folder_viewer"
  title       = "Folder Viewer"
  description = "Descoped viewer for folder resources"
  permissions = [
    "resourcemanager.folders.get",
    "resourcemanager.folders.getIamPolicy",
    "resourcemanager.folders.list",
    "resourcemanager.folders.searchPolicyBindings",
  ]
}

module "custom_role_logging_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "logging_viewer"
  title       = "Logging Viewer"
  description = "Descoped viewer for Cloud Logging resources"
  permissions = [
    "logging.buckets.get",
    "logging.buckets.list",
    "logging.buckets.listEffectiveTags",
    "logging.buckets.listTagBindings",
    "logging.exclusions.get",
    "logging.exclusions.list",
    "logging.fields.access",
    "logging.links.get",
    "logging.links.list",
    "logging.locations.get",
    "logging.locations.list",
    "logging.logEntries.list",
    "logging.logMetrics.get",
    "logging.logMetrics.list",
    "logging.logs.list",
    "logging.logScopes.get",
    "logging.logScopes.list",
    "logging.logServiceIndexes.list",
    "logging.logServices.list",
    "logging.notificationRules.get",
    "logging.notificationRules.list",
    "logging.operations.get",
    "logging.operations.list",
    "logging.privateLogEntries.list",
    "logging.queries.getShared",
    "logging.queries.listShared",
    "logging.settings.get",
    "logging.sinks.get",
    "logging.sinks.list",
    "logging.usage.get",
    "logging.views.get",
    "logging.views.getIamPolicy",
    "logging.views.list",
    "logging.views.listLogs",
    "logging.views.listResourceKeys",
    "logging.views.listResourceValues",
    "observability.scopes.get",
    "resourcemanager.projects.get",
    "resourcemanager.projects.list",
    "resourcemanager.tagHolds.list",
    "resourcemanager.tagKeys.get",
    "resourcemanager.tagKeys.getIamPolicy",
    "resourcemanager.tagKeys.list",
    "resourcemanager.tagValues.get",
    "resourcemanager.tagValues.getIamPolicy",
    "resourcemanager.tagValues.list",
  ]
}

module "custom_role_network_firewall_policies_admin" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "network_firewall_policies_admin"
  title       = "Network Firewall Policies Admin"
  description = "Admin for network firewall policies and endpoint associations"
  permissions = [
    "compute.networks.setFirewallPolicy",
    "networksecurity.firewallEndpointAssociations.create",
    "networksecurity.firewallEndpointAssociations.delete",
    "networksecurity.firewallEndpointAssociations.get",
    "networksecurity.firewallEndpointAssociations.list",
    "networksecurity.firewallEndpointAssociations.update",
  ]
}

module "custom_role_ngfw_enterprise_admin" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "ngfw_enterprise_admin"
  title       = "NGFW Enterprise Admin"
  description = "Used by the networking SA to deploy NGFW Enterprise through the addon"
  permissions = [
    "networksecurity.firewallEndpoints.create",
    "networksecurity.firewallEndpoints.delete",
    "networksecurity.firewallEndpoints.get",
    "networksecurity.firewallEndpoints.list",
    "networksecurity.firewallEndpoints.update",
    "networksecurity.firewallEndpoints.use",
    "networksecurity.locations.get",
    "networksecurity.locations.list",
    "networksecurity.operations.cancel",
    "networksecurity.operations.delete",
    "networksecurity.operations.get",
    "networksecurity.operations.list",
    "networksecurity.securityProfileGroups.create",
    "networksecurity.securityProfileGroups.delete",
    "networksecurity.securityProfileGroups.get",
    "networksecurity.securityProfileGroups.list",
    "networksecurity.securityProfileGroups.update",
    "networksecurity.securityProfileGroups.use",
    "networksecurity.securityProfiles.create",
    "networksecurity.securityProfiles.delete",
    "networksecurity.securityProfiles.get",
    "networksecurity.securityProfiles.list",
    "networksecurity.securityProfiles.update",
    "networksecurity.securityProfiles.use",
    "networksecurity.tlsInspectionPolicies.create",
    "networksecurity.tlsInspectionPolicies.delete",
    "networksecurity.tlsInspectionPolicies.get",
    "networksecurity.tlsInspectionPolicies.list",
    "networksecurity.tlsInspectionPolicies.update",
    "networksecurity.tlsInspectionPolicies.use",
  ]
}

module "custom_role_ngfw_enterprise_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "ngfw_enterprise_viewer"
  title       = "NGFW Enterprise Viewer"
  description = "Used by the networking SA to view NGFW Enterprise resources"
  permissions = [
    "networksecurity.firewallEndpoints.get",
    "networksecurity.firewallEndpoints.list",
    "networksecurity.firewallEndpoints.use",
    "networksecurity.locations.get",
    "networksecurity.locations.list",
    "networksecurity.operations.get",
    "networksecurity.operations.list",
    "networksecurity.securityProfileGroups.get",
    "networksecurity.securityProfileGroups.list",
    "networksecurity.securityProfileGroups.use",
    "networksecurity.securityProfiles.get",
    "networksecurity.securityProfiles.list",
    "networksecurity.securityProfiles.use",
    "networksecurity.tlsInspectionPolicies.get",
    "networksecurity.tlsInspectionPolicies.list",
    "networksecurity.tlsInspectionPolicies.use",
  ]
}

module "custom_role_organization_admin_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "organization_admin_viewer"
  title       = "Organization Admin Viewer"
  description = "Used by the plan-only admin SA"
  permissions = [
    "essentialcontacts.contacts.get",
    "essentialcontacts.contacts.list",
    "logging.settings.get",
    "orgpolicy.constraints.list",
    "orgpolicy.policies.list",
    "orgpolicy.policy.get",
    "resourcemanager.folders.get",
    "resourcemanager.folders.getIamPolicy",
    "resourcemanager.folders.list",
    "resourcemanager.organizations.get",
    "resourcemanager.organizations.getIamPolicy",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.list",
    "storage.buckets.getIamPolicy",
  ]
}

module "custom_role_organization_iam_admin" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "organization_iam_admin"
  title       = "Organization IAM Admin"
  description = "Needed for use in additive IAM bindings to avoid conflicts"
  permissions = [
    "resourcemanager.organizations.get",
    "resourcemanager.organizations.getIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
  ]
}

module "custom_role_project_iam_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "project_iam_viewer"
  title       = "Project IAM Viewer"
  description = "Used by the plan-only admin SA"
  permissions = [
    "iam.policybindings.get",
    "iam.policybindings.list",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.searchPolicyBindings",
  ]
}

module "custom_role_service_account_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "service_account_viewer"
  title       = "Service Account Viewer"
  description = "Descoped viewer for service account resources"
  permissions = [
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.getIamPolicy",
    "iam.serviceAccounts.list",
  ]
}

module "custom_role_service_networking_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "service_networking_viewer"
  title       = "Service Networking Viewer"
  description = "Descoped viewer for service networking resources"
  permissions = [
    "servicenetworking.operations.get",
    "servicenetworking.operations.list",
    "servicenetworking.services.get",
    "servicenetworking.services.getConsumerConfig",
    "servicenetworking.services.getVpcServiceControls",
    "servicenetworking.services.listPeeredDnsDomains",
  ]
}

module "custom_role_service_project_network_admin" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "service_project_network_admin"
  title       = "Service Project Network Admin"
  description = "Admin for service project network operations including peering and XPN"
  permissions = [
    "compute.globalOperations.get",
    "compute.networks.updatePeering",
    "compute.networks.get",
    "compute.organizations.disableXpnResource",
    "compute.organizations.enableXpnResource",
    "compute.projects.get",
    "compute.subnetworks.getIamPolicy",
    "compute.subnetworks.setIamPolicy",
    "dns.networks.bindPrivateDNSZone",
    "resourcemanager.projects.get",
  ]
}

module "custom_role_storage_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "storage_viewer"
  title       = "Storage Viewer"
  description = "Descoped viewer for Cloud Storage resources"
  permissions = [
    "storage.buckets.get",
    "storage.buckets.getIamPolicy",
    "storage.buckets.getObjectInsights",
    "storage.buckets.list",
    "storage.buckets.listEffectiveTags",
    "storage.buckets.listTagBindings",
    "storage.managedFolders.get",
    "storage.managedFolders.getIamPolicy",
    "storage.managedFolders.list",
    "storage.multipartUploads.list",
    "storage.multipartUploads.listParts",
    "storage.objects.get",
    "storage.objects.getIamPolicy",
    "storage.objects.list",
  ]
}

module "custom_role_tag_viewer" {
  source = "./modules/custom-role"

  org_id      = var.org_id
  role_id     = "tag_viewer"
  title       = "Tag Viewer"
  description = "Descoped viewer for tag resources"
  permissions = [
    "resourcemanager.tagHolds.list",
    "resourcemanager.tagKeys.get",
    "resourcemanager.tagKeys.getIamPolicy",
    "resourcemanager.tagKeys.list",
    "resourcemanager.tagValues.get",
    "resourcemanager.tagValues.getIamPolicy",
    "resourcemanager.tagValues.list",
  ]
}

# ---------------------------------------------------------------------------
# Org-level IAM
# ---------------------------------------------------------------------------

module "org_iam" {
  source = "./modules/iam"

  resource_id = "organizations/${var.org_id}"

  authoritative_bindings = {
    "roles/owner"                             = ["group:${var.admin_group_email}"]
    "roles/resourcemanager.organizationAdmin" = ["group:${var.admin_group_email}"]
    "roles/resourcemanager.folderAdmin"       = ["group:${var.admin_group_email}"]
    "roles/resourcemanager.projectCreator"    = ["group:${var.admin_group_email}"]
    "roles/orgpolicy.policyAdmin"             = ["group:${var.admin_group_email}"]
    "roles/resourcemanager.tagAdmin"          = ["group:${var.admin_group_email}"]
    "roles/cloudasset.owner"                  = ["group:${var.admin_group_email}"]
    "roles/compute.xpnAdmin"                  = ["group:${var.admin_group_email}"]
    "roles/iam.workforcePoolAdmin"            = ["group:${var.admin_group_email}"]
    "roles/iam.principalAccessBoundaryAdmin"  = ["group:${var.admin_group_email}"]
    "roles/cloudsupport.admin"                = ["group:${var.admin_group_email}"]
    "roles/cloudsupport.techSupportEditor"    = ["group:${var.admin_group_email}"]
    "roles/compute.osAdminLogin"              = ["group:${var.admin_group_email}"]
    "roles/compute.osLoginExternalUser"       = ["group:${var.admin_group_email}"]
    "roles/billing.creator"                   = []
  }

  additive_bindings = {
    iac_org_admin = {
      role   = "roles/resourcemanager.organizationAdmin"
      member = "serviceAccount:${var.iac_sa_email}"
    }
    iac_folder_admin = {
      role   = "roles/resourcemanager.folderAdmin"
      member = "serviceAccount:${var.iac_sa_email}"
    }
    iac_orgpolicy_admin = {
      role   = "roles/orgpolicy.policyAdmin"
      member = "serviceAccount:${var.iac_sa_email}"
    }
    iac_role_admin = {
      role   = "roles/iam.organizationRoleAdmin"
      member = "serviceAccount:${var.iac_sa_email}"
    }
    iac_logging_admin = {
      role   = "roles/logging.admin"
      member = "serviceAccount:${var.iac_sa_email}"
    }
    iac_assured_workloads_admin = {
      role   = "roles/assuredworkloads.admin"
      member = "serviceAccount:${var.iac_sa_email}"
    }
    iac_cloudasset_owner = {
      role   = "roles/cloudasset.owner"
      member = "serviceAccount:${var.iac_sa_email}"
    }
    iac_acm_policy_admin = {
      role   = "roles/accesscontextmanager.policyAdmin"
      member = "serviceAccount:${var.iac_sa_email}"
    }
  }
}

# ---------------------------------------------------------------------------
# Data access logging
# ---------------------------------------------------------------------------

resource "google_organization_iam_audit_config" "org" {
  org_id  = "organizations/${var.org_id}"
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
}

# ---------------------------------------------------------------------------
# Org-level log sinks
# ---------------------------------------------------------------------------

resource "google_logging_organization_sink" "audit_logs" {
  name             = "audit-logs"
  org_id           = var.org_id
  include_children = true
  destination      = var.log_bucket_name

  filter = "logName:(\"/logs/cloudaudit.googleapis.com%2Factivity\" OR \"/logs/cloudaudit.googleapis.com%2Fsystem_event\" OR \"/logs/cloudaudit.googleapis.com%2Fpolicy\" OR \"/logs/cloudaudit.googleapis.com%2Faccess_transparency\")"
}

resource "google_logging_organization_sink" "iam" {
  name             = "iam"
  org_id           = var.org_id
  include_children = true
  destination      = var.log_bucket_name

  filter = "protoPayload.serviceName=(\"iamcredentials.googleapis.com\" OR \"iam.googleapis.com\" OR \"sts.googleapis.com\")"
}

resource "google_logging_organization_sink" "vpc_sc" {
  name             = "vpc-sc"
  org_id           = var.org_id
  include_children = true
  destination      = var.log_bucket_name

  filter = "protoPayload.metadata.@type=\"type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata\""
}
