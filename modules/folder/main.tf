resource "google_folder" "folder" {
  display_name = var.name
  parent       = var.parent

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_folder_iam_binding" "bindings" {
  for_each = var.iam_bindings
  folder   = google_folder.folder.id
  role     = each.key
  members  = each.value
}
