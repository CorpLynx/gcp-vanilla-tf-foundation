variable "name" {
  description = "Folder display name."
  type        = string
}

variable "parent" {
  description = "Parent resource ID in the form 'organizations/ORG_ID' or 'folders/FOLDER_ID'."
  type        = string
}

variable "iam_bindings" {
  description = "Authoritative IAM bindings for the folder. Map of role => list of members."
  type        = map(list(string))
  default     = {}
}
