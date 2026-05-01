locals {
  prefix   = var.prefix == null ? "" : "${var.prefix}-"
  sa_email = (
    var.project_id != null
    ? "${local.prefix}${var.name}@${var.project_id}.iam.gserviceaccount.com"
    : var.name
  )
  iam_email = "serviceAccount:${local.sa_email}"
}

resource "google_service_account" "sa" {
  count        = var.create ? 1 : 0
  project      = var.project_id
  account_id   = "${local.prefix}${var.name}"
  display_name = coalesce(var.display_name, "${local.prefix}${var.name}")
  description  = var.description
}
