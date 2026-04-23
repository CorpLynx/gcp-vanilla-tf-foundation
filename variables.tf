variable "org_id" {
  description = "GCP organization numeric ID."
  type        = string
  default     = "1041701195417"
}

variable "billing_account" {
  description = "Billing account ID to associate with projects."
  type        = string
}

variable "org_domain" {
  description = "Organization domain (e.g. example.com)."
  type        = string
}

variable "iac_sa_email" {
  description = "IaC service account email used for provider impersonation."
  type        = string
}

variable "iac_project_id" {
  description = "GCP project ID that hosts the IaC service accounts (used in org-policy CEL conditions)."
  type        = string
}

variable "admin_group_email" {
  description = "Admin Google Workspace group email (e.g. gcp-organization-admins@example.com)."
  type        = string
}

variable "tfc_organization" {
  description = "Terraform Cloud / Enterprise organization name."
  type        = string
}

variable "tfc_workspace" {
  description = "Terraform Cloud / Enterprise workspace name."
  type        = string
}

variable "log_bucket_name" {
  description = "Destination log bucket resource name for org-level log sinks."
  type        = string
}

variable "primary_location" {
  description = "Primary GCP region. Must be a US region (must start with 'us-') to satisfy FedRAMP High data residency requirements."
  type        = string
  default     = "us-east4"

  validation {
    condition     = startswith(var.primary_location, "us-")
    error_message = "primary_location must be a US region (value must start with 'us-'). FedRAMP High requires data residency within the United States."
  }
}
