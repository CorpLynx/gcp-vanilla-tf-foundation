output "id" {
  description = "Project ID."
  value       = google_project.project.project_id
}

output "number" {
  description = "Numeric project number."
  value       = google_project.project.number
}

output "name" {
  description = "Project display name."
  value       = google_project.project.name
}
