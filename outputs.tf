output "folder_ids" {
  description = "Map of folder name to fully-qualified folder ID."
  value = {
    test          = google_folder.test.id
    tld_aw_folder = google_folder.tld_aw_folder.id
  }
}
