output "custom_role_ids" {
  description = "Map of custom role ID to fully qualified role name."
  value = {
    for k, v in google_organization_iam_custom_role.roles : k => v.id
  }
}

output "org_policy_ids" {
  description = "List of org policy resource names."
  value       = [for v in google_org_policy_policy.default : v.name]
}
