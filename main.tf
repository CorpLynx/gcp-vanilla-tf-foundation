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
  # Filter by resource_type to safely get the CONSUMER_FOLDER regardless of index order
  aw_folder_id = "folders/${[
    for r in google_assured_workloads_workload.frh.resources :
    r.resource_id if r.resource_type == "CONSUMER_FOLDER"
  ][0]}"
}

# Static top-level folders — stable org structure, named resources

resource "google_folder" "tld_aw_folder" {
  display_name = "Assured Workloads"
  parent       = "organizations/${var.org.id}"
}

resource "google_assured_workloads_workload" "frh" {
  compliance_regime = "FEDRAMP_HIGH"
  display_name      = "FedRAMP High Workload"
  location          = var.region
  organization      = var.org.id
  billing_account   = "billingAccounts/${var.billing_account}"

  kms_settings {
    next_rotation_time = "9999-10-02T15:01:23Z"
    rotation_period    = "10368000s"
  }

  provisioned_resources_parent = google_folder.tld_aw_folder.id

  resource_settings {
    display_name  = "FRH-Folder"
    resource_type = "CONSUMER_FOLDER"
  }

  # resource_settings {
  #   resource_type = "ENCRYPTION_KEYS_PROJECT"
  # }

  # resource_settings {
  #   resource_id   = "ring"
  #   resource_type = "KEYRING"
  # }

  violation_notifications_enabled = true

  # workload_options {
  #   kaj_enrollment_type = "KEY_ACCESS_TRANSPARENCY_OFF"
  # }

  labels = var.default_labels
}


resource "google_project" "vanilla_iac_core" {
  name            = "vanilla-iac-core"
  project_id      = "vanilla-iac-core"
  folder_id       = local.aw_folder_id
  billing_account = var.billing_account
}


resource "google_project" "vanilla_billing_core" {
  name            = "vanilla-billing-core"
  project_id      = "vanilla-billing-core"
  folder_id       = local.aw_folder_id
  billing_account = var.billing_account
}


resource "google_project" "vanilla_log_core" {
  name            = "vanilla-log-core"
  project_id      = "vanilla-log-core"
  folder_id       = local.aw_folder_id
  billing_account = var.billing_account
}


resource "google_folder" "networking" {
  display_name = "Networking"
  parent = local.aw_folder_id
}

resource "google_folder" "security" {
  display_name = "Security"
  parent = local.aw_folder_id
}

resource "google_folder" "shared_services" {
  display_name = "Shared Services"
  parent = local.aw_folder_id
}

resource "google_folder" "workloads" {
  display_name = "Workloads"
  parent = local.aw_folder_id
}
