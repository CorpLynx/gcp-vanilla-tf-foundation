output "id" {
  description = "Fully-qualified folder resource ID (folders/FOLDER_ID)."
  value       = google_folder.folder.id
}

output "name" {
  description = "Folder display name."
  value       = google_folder.folder.display_name
}
