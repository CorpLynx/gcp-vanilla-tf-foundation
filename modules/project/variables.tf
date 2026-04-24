variable "name" {
  description = "Project display name."
  type        = string
}

variable "project_id" {
  description = "Globally unique project ID."
  type        = string
}

variable "folder_id" {
  description = "Parent folder resource ID in the form folders/FOLDER_ID."
  type        = string

  validation {
    condition     = can(regex("^folders/[0-9]+$", var.folder_id))
    error_message = "folder_id must be in the form folders/FOLDER_ID (e.g. folders/123456789)."
  }
}

variable "billing_account" {
  description = "Billing account ID to associate with the project."
  type        = string
}

variable "labels" {
  description = "Resource labels to apply to the project."
  type        = map(string)
  default     = {}
}
