output "folder_ids" {
  description = "Map of folder display name to fully-qualified folder ID."
  value = {
    aw_root      = module.folder_aw_root.id
    fedramp_high = module.folder_fedramp_high.id
  }
}

output "custom_role_ids" {
  description = "Map of custom role short name to fully-qualified role ID."
  value = {
    cloudkms_viewer                 = module.custom_role_cloudkms_viewer.id
    folder_viewer                   = module.custom_role_folder_viewer.id
    logging_viewer                  = module.custom_role_logging_viewer.id
    network_firewall_policies_admin = module.custom_role_network_firewall_policies_admin.id
    ngfw_enterprise_admin           = module.custom_role_ngfw_enterprise_admin.id
    ngfw_enterprise_viewer          = module.custom_role_ngfw_enterprise_viewer.id
    organization_admin_viewer       = module.custom_role_organization_admin_viewer.id
    organization_iam_admin          = module.custom_role_organization_iam_admin.id
    project_iam_viewer              = module.custom_role_project_iam_viewer.id
    service_account_viewer          = module.custom_role_service_account_viewer.id
    service_networking_viewer       = module.custom_role_service_networking_viewer.id
    service_project_network_admin   = module.custom_role_service_project_network_admin.id
    storage_viewer                  = module.custom_role_storage_viewer.id
    tag_viewer                      = module.custom_role_tag_viewer.id
  }
}

output "org_policy_ids" {
  description = "List of applied org policy resource IDs."
  value       = module.org_policy.policy_ids
}

output "audit_config_id" {
  description = "Audit config resource ID."
  value       = google_organization_iam_audit_config.org.id
}
