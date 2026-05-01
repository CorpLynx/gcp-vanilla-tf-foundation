variable "name" {
  description = "Folder display name."
  type        = string
}

variable "parent" {
  description = "Parent resource in organizations/NNNN or folders/NNNN format."
  type        = string
}

variable "deletion_protection" {
  description = "Prevent Terraform from destroying the folder."
  type        = bool
  default     = false
}

variable "iam" {
  description = "Authoritative IAM bindings. Map of role => list of members. Replaces all members for each role."
  type        = map(list(string))
  default     = {}
}

variable "iam_conditions" {
  description = "Optional IAM conditions keyed by role, applied to authoritative bindings."
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
