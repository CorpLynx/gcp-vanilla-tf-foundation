variable "resource_id" {
  description = "The organization resource ID (e.g., organizations/1041701195417)."
  type        = string
}

variable "authoritative_bindings" {
  description = "Map of role to list of members for authoritative IAM bindings (google_organization_iam_binding). Replaces all existing members for each role."
  type        = map(list(string))
  default     = {}
}

variable "additive_bindings" {
  description = "Map of binding key to role/member object for additive IAM bindings (google_organization_iam_member). Does not disturb other members of the role."
  type = map(object({
    role   = string
    member = string
  }))
  default = {}
}
