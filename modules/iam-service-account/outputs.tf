output "email" {
  description = "Service account email."
  value       = local.sa_email
}

output "iam_email" {
  description = "Service account email in serviceAccount: format for IAM bindings."
  value       = local.iam_email
}

output "id" {
  description = "Fully qualified service account resource ID."
  value       = var.create ? google_service_account.sa[0].id : null
}

output "name" {
  description = "Service account resource name (projects/.../serviceAccounts/...)."
  value       = var.create ? google_service_account.sa[0].name : null
}
