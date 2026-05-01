variable "org_id" {
  description = "GCP organization numeric ID."
  type        = string
}

variable "iam" {
  description = "Authoritative IAM bindings at org level. Map of role => list of members."
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

variable "custom_roles" {
  description = "Custom IAM roles to create at org level."
  type = map(object({
    title       = string
    description = optional(string)
    permissions = list(string)
    stage       = optional(string, "GA")
  }))
  default = {}
}

variable "org_policies" {
  description = "Org policies to apply. Map of constraint => policy spec."
  type = map(object({
    inherit_from_parent = optional(bool)
    reset               = optional(bool)
    rules = optional(list(object({
      deny_all  = optional(string)
      allow_all = optional(string)
      enforce   = optional(string)
      condition = optional(object({
        description = optional(string)
        expression  = optional(string)
        location    = optional(string)
        title       = optional(string)
      }))
      values = optional(object({
        allowed_values = optional(list(string))
        denied_values  = optional(list(string))
      }))
    })), [])
  }))
  default = {}
}
