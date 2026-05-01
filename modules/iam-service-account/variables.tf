variable "name" {
  description = "Service account name (account_id portion, without @project.iam...)."
  type        = string
}

variable "project_id" {
  description = "Project where the service account will be created."
  type        = string
  default     = null
}

variable "prefix" {
  description = "Optional prefix prepended to the account ID."
  type        = string
  default     = null
}

variable "display_name" {
  description = "Human-readable display name."
  type        = string
  default     = null
}

variable "description" {
  description = "Service account description."
  type        = string
  default     = null
}

variable "create" {
  description = "Set to false to manage IAM for an existing SA without creating it."
  type        = bool
  default     = true
}

variable "iam" {
  description = "Authoritative IAM bindings on this SA (who can impersonate/use it). Map of role => members."
  type        = map(list(string))
  default     = {}
}

variable "iam_members" {
  description = "Additive IAM bindings on this SA. Map of key => {role, member}."
  type = map(object({
    role   = string
    member = string
  }))
  default = {}
}

variable "iam_project_roles" {
  description = "Roles to grant this SA on specific projects. Map of project_id => list of roles."
  type        = map(list(string))
  default     = {}
}

variable "iam_folder_roles" {
  description = "Roles to grant this SA on specific folders. Map of folder_id => list of roles."
  type        = map(list(string))
  default     = {}
}

variable "iam_org_roles" {
  description = "Roles to grant this SA at org level. Map of org_id => list of roles."
  type        = map(list(string))
  default     = {}
}
