resource "google_project" "project" {
  name            = var.name
  project_id      = var.project_id
  folder_id       = var.folder_id
  billing_account = var.billing_account
  labels          = var.labels

  auto_create_network = false
}
