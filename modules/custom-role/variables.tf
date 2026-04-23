variable "org_id" {
  description = "Numeric GCP organization ID"
  type        = string
}

variable "role_id" {
  description = "Short role ID (e.g., cloudkms_viewer)"
  type        = string
}

variable "title" {
  description = "Human-readable title for the custom role"
  type        = string
}

variable "description" {
  description = "Description of the custom role"
  type        = string
}

variable "permissions" {
  description = "List of IAM permissions granted by this role"
  type        = list(string)
}
