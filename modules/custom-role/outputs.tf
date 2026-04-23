output "id" {
  description = "Fully-qualified custom role ID (organizations/ORG_ID/roles/ROLE_ID)"
  value       = google_organization_iam_custom_role.role.id
}
