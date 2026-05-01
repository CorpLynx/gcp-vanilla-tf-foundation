variable "name" {
  description = "Project ID suffix (prefix will be prepended if set)."
  type        = string
}

variable "display_name" {
  description = "Human-readable project name. Defaults to project ID."
  type        = string
  default     = null
}

variable "prefix" {
  description = "Optional prefix prepended to the project ID."
  type        = string
  default     = null
}

variable "parent" {
  description = "Parent in organizations/NNNN or folders/NNNN format."
  type        = string
  default     = null
}

variable "billing_account" {
  description = "Billing account ID to associate with the project."
  type        = string
}

variable "services" {
  description = "List of GCP APIs to enable on the project."
  type        = list(string)
  default     = []
}

variable "disable_services_on_destroy" {
  description = "Disable services when the project is destroyed."
  type        = bool
  default     = false
}

variable "auto_create_network" {
  description = "Create the default VPC network."
  type        = bool
  default     = false
}

variable "labels" {
  description = "Resource labels."
  type        = map(string)
  default     = {}
}

variable "deletion_policy" {
  description = "Project deletion policy. One of DELETE, PREVENT, ABANDON."
  type        = string
  default     = "PREVENT"
}

variable "lien_reason" {
  description = "If set, creates a lien to prevent project deletion."
  type        = string
  default     = null
}

variable "iam" {
  description = "Authoritative IAM bindings. Map of role => list of members."
  type        = map(list(string))
  default     = {}
}

variable "iam_conditions" {
  description = "Optional IAM conditions keyed by role."
  type = map(object({
    title       = string
    description = optional(string)
    expression  = string
  }))
  default = {}
}

variable "iam_members" {
  description = "Additive IAM bindings. Map of key => {role, member, optional condition}."
  type = map(object({
    role   = string
    member = string
    condition = optional(object({
      title       = string
      description = optional(string)
      expression  = string
    }))
  }))
  default = {}
}
