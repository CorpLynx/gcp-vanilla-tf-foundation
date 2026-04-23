resource "google_organization_iam_custom_role" "role" {
  org_id      = var.org_id
  role_id     = var.role_id
  title       = var.title
  description = var.description
  permissions = var.permissions
  stage       = "GA"
}
