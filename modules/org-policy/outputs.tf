output "constraint_names" {
  description = "List of custom constraint names created by this module."
  value       = [for k, _ in google_org_policy_custom_constraint.constraint : k]
}

output "policy_ids" {
  description = "List of org policy resource IDs created by this module."
  value       = [for _, p in google_org_policy_policy.policy : p.id]
}
