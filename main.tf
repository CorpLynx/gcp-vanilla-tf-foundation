# Hashicorp recommends putting the terraform block (including required_version,
# required_providers, and backend) in a dedicated versions.tf file.
terraform {
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 6.0"
    }
  }

  # Hashicorp recommends putting backend config in a dedicated backend.tf file.
  # Note: the cloud block does not support variable interpolation - values must
  # be hardcoded or passed via TF_CLOUD_ORGANIZATION / TF_WORKSPACE env vars.
  cloud {
    organization = "corplynx-lab"
    hostname     = "app.terraform.io"

    workspaces {
      name = "gcp-vanilla"
    }
  }
}

# Hashicorp recommends putting provider blocks in a dedicated providers.tf file.
provider "google" {}

provider "google-beta" {}

locals {
  # Produces "cl1-" or "" if no prefix is set
  prefix = var.prefix != "" ? "${var.prefix}-" : ""

  # Filter by resource_type to safely get the CONSUMER_FOLDER regardless of index order
  aw_folder_id = "folders/${[
    for r in google_assured_workloads_workload.frh.resources :
    r.resource_id if r.resource_type == "CONSUMER_FOLDER"
  ][0]}"
}

# Static top-level folders — stable org structure, named resources

resource "google_folder" "tld_aw_folder" {
  display_name        = "${local.prefix}assured-workloads"
  parent              = "organizations/${var.org.id}"
  deletion_protection = var.deletion_protection
}

resource "google_assured_workloads_workload" "frh" {
  compliance_regime = "FEDRAMP_HIGH"
  display_name      = "${local.prefix}fedramp-high"
  location          = var.region
  organization      = var.org.id
  billing_account   = "billingAccounts/${var.billing_account}"

  kms_settings {
    next_rotation_time = "9999-10-02T15:01:23Z"
    rotation_period    = "10368000s"
  }

  provisioned_resources_parent = google_folder.tld_aw_folder.id

  resource_settings {
    display_name  = "${local.prefix}frh-folder"
    resource_type = "CONSUMER_FOLDER"
  }

  violation_notifications_enabled = true

  labels = var.default_labels
}

resource "google_project" "iac_core" {
  name            = "${local.prefix}iac-core"
  project_id      = "${local.prefix}iac-core"
  folder_id       = local.aw_folder_id
  billing_account = var.billing_account
  deletion_policy = var.deletion_protection ? "PREVENT" : "DELETE"
}

resource "google_project" "billing_core" {
  name            = "${local.prefix}billing-core"
  project_id      = "${local.prefix}billing-core"
  folder_id       = local.aw_folder_id
  billing_account = var.billing_account
  deletion_policy = var.deletion_protection ? "PREVENT" : "DELETE"
}

resource "google_project" "log_core" {
  name            = "${local.prefix}log-core"
  project_id      = "${local.prefix}log-core"
  folder_id       = local.aw_folder_id
  billing_account = var.billing_account
  deletion_policy = var.deletion_protection ? "PREVENT" : "DELETE"
}

resource "google_folder" "networking" {
  display_name        = "${local.prefix}networking"
  parent              = local.aw_folder_id
  deletion_protection = var.deletion_protection
}

resource "google_folder" "security" {
  display_name        = "${local.prefix}security"
  parent              = local.aw_folder_id
  deletion_protection = var.deletion_protection
}

resource "google_folder" "shared_services" {
  display_name        = "${local.prefix}shared-services"
  parent              = local.aw_folder_id
  deletion_protection = var.deletion_protection
}

resource "google_folder" "workloads" {
  display_name        = "${local.prefix}workloads"
  parent              = local.aw_folder_id
  deletion_protection = var.deletion_protection
}
