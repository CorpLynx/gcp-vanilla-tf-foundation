# Moved blocks tell Terraform that existing state entries have been renamed/moved
# without destroying and recreating the underlying GCP resources.

moved {
  from = google_assured_workloads_workload.frh
  to   = module.frh.google_assured_workloads_workload.this
}
