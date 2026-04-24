output "id" {
  description = "Fully-qualified project resource name (projects/PROJECT_ID)."
  value       = google_project.project.id
}

output "project_id" {
  description = "Plain project ID string."
  value       = google_project.project.project_id
}

output "number" {
  description = "Numeric GCP project number."
  value       = google_project.project.number
}
