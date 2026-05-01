resource "google_assured_workloads_workload" "frh" {
  compliance_regime = var.compliance_regime
  display_name      = var.display_name
  location          = var.location
  organization      = var.organization
  billing_account   = "billingAccounts/${var.billing_account}"

  kms_settings {
    next_rotation_time = var.kms_next_rotation_time
    rotation_period    = var.kms_rotation_period
  }

  provisioned_resources_parent = var.parent_folder_id

  resource_settings {
    display_name  = "${var.display_name}-folder"
    resource_type = "CONSUMER_FOLDER"
  }

  violation_notifications_enabled = var.violation_notifications_enabled

  labels = var.labels
}
