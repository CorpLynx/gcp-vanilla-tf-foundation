output "consumer_folder_id" {
  description = "Fully qualified folder ID (folders/NNNN) of the AW-managed CONSUMER_FOLDER."
  # Reference the workload resource directly so Terraform preserves the dependency
  # edge during destroy — child resources referencing this output will be destroyed
  # before the workload itself.
  value = "folders/${[
    for r in google_assured_workloads_workload.frh.resources :
    r.resource_id if r.resource_type == "CONSUMER_FOLDER"
  ][0]}"

  depends_on = [google_assured_workloads_workload.this]
}

output "workload_name" {
  description = "Fully qualified workload resource name."
  value       = google_assured_workloads_workload.this.name
}

output "workload_id" {
  description = "Workload resource ID."
  value       = google_assured_workloads_workload.this.id
}
