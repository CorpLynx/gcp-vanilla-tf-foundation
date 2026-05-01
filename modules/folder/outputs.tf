output "id" {
  description = "Fully qualified folder ID (folders/NNNN)."
  value       = google_folder.folder.id
}

output "name" {
  description = "Folder display name."
  value       = google_folder.folder.display_name
}

output "number" {
  description = "Numeric folder ID."
  value       = split("/", google_folder.folder.id)[1]
}
