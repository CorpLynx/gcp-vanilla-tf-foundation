variable "org" {
  description = "general organization variables"
  type = map(string)
  default = {
    domain = "gigachadglobal.org"
    id     = "1041701195417"
  }
}

variable "billing_account" {
  description = "Billing account ID to associate with projects."
  type        = string
  default     = "014F76-ED4E67-7CCCE1"
}

# variable "iac_project_id" {
#   description = "GCP project ID that hosts the IaC service accounts (used in org-policy CEL conditions)."
#   type        = string
# }

# variable "admin_group_email" {
#   description = "Admin Google Workspace group email (e.g. gcp-organization-admins@example.com)."
#   type        = string
# }

# variable "log_bucket_name" {
#   description = "Destination log bucket resource name for org-level log sinks."
#   type        = string
# }

variable "region" {
  description = "Primary GCP region. Must be a US region (must start with 'us-') to satisfy FedRAMP High data residency requirements."
  type        = string
  default     = "us-central1"

  validation {
    condition     = startswith(var.region, "us-")
    error_message = "primary_location must be a US region (value must start with 'us-'). FedRAMP High requires data residency within the United States."
  }
}


variable "default_labels" {
type = map(string)
default = {
  "managed-by"        = "terraform"
  "owner"             = "myteam"
  "compliance-regime" = "frh"
}
}