variable "compliance_regime" {
  description = "Compliance regime for the workload (e.g. FEDRAMP_HIGH, FEDRAMP_MODERATE)."
  type        = string
}

variable "display_name" {
  description = "Display name for the workload."
  type        = string
}

variable "location" {
  description = "GCP region for the workload control plane."
  type        = string
}

variable "organization" {
  description = "GCP organization numeric ID."
  type        = string
}

variable "billing_account" {
  description = "Billing account ID (without billingAccounts/ prefix)."
  type        = string
}

variable "parent_folder_id" {
  description = "Parent folder ID in folders/NNNN format. AW will provision its managed folder inside this."
  type        = string
}

variable "kms_next_rotation_time" {
  description = "Next KMS key rotation time in RFC3339 format."
  type        = string
  default     = "9999-10-02T15:01:23Z"
}

variable "kms_rotation_period" {
  description = "KMS key rotation period in seconds."
  type        = string
  default     = "10368000s"
}

variable "violation_notifications_enabled" {
  description = "Send notifications when workload drifts out of compliance."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Labels to apply to the workload."
  type        = map(string)
  default     = {}
}
