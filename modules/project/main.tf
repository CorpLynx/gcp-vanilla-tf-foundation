locals {
  prefix     = var.prefix == null ? "" : "${var.prefix}-"
  project_id = "${local.prefix}${var.name}"
  parent_type = (
    var.parent == null ? null
    : startswith(var.parent, "organizations") ? "organizations"
    : "folders"
  )
  parent_id = var.parent == null ? null : split("/", var.parent)[1]
}

resource "google_project" "project" {
  project_id          = local.project_id
  name                = coalesce(var.display_name, local.project_id)
  billing_account     = var.billing_account
  org_id              = local.parent_type == "organizations" ? local.parent_id : null
  folder_id           = local.parent_type == "folders" ? local.parent_id : null
  auto_create_network = var.auto_create_network
  labels              = var.labels
  deletion_policy     = var.deletion_policy
}

resource "google_project_service" "services" {
  for_each                   = toset(var.services)
  project                    = google_project.project.project_id
  service                    = each.value
  disable_on_destroy         = var.disable_services_on_destroy
  disable_dependent_services = false
}

# Optional: prevent accidental project deletion
resource "google_resource_manager_lien" "lien" {
  count        = var.lien_reason != null ? 1 : 0
  parent       = "projects/${google_project.project.number}"
  restrictions = ["resourcemanager.projects.delete"]
  origin       = "created-by-terraform"
  reason       = var.lien_reason
}
