variable "org_id" {
  description = "Numeric GCP organization ID."
  type        = string
}

variable "custom_constraints" {
  description = "Map of constraint name to custom constraint configuration."
  type = map(object({
    resource_types = list(string)
    method_types   = list(string)
    condition      = string
    action_type    = string
    display_name   = string
    description    = optional(string, "")
  }))
  default = {}
}

variable "policies" {
  description = "Map of constraint name to org policy rules."
  type = map(object({
    rules = list(object({
      enforce   = optional(bool)
      allow_all = optional(bool)
      deny_all  = optional(bool)
      values = optional(object({
        allow = optional(list(string), [])
        deny  = optional(list(string), [])
      }))
      condition = optional(object({
        title      = string
        expression = string
      }))
    }))
  }))
  default = {}
}
