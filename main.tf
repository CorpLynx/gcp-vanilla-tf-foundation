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
}

# Top-level folder that contains the AW workload
resource "google_folder" "tld_aw_folder" {
  display_name        = "${local.prefix}assured-workloads"
  parent              = "organizations/${var.org.id}"
  deletion_protection = var.deletion_protection
}

# Assured Workloads module — outputs consumer_folder_id as a resource reference
# so Terraform correctly orders destroy (children before workload)
module "frh" {
  source = "./modules/assured-workload"

  compliance_regime               = "FEDRAMP_HIGH"
  display_name                    = "${local.prefix}fedramp-high"
  location                        = var.region
  organization                    = var.org.id
  billing_account                 = var.billing_account
  parent_folder_id                = google_folder.tld_aw_folder.id
  violation_notifications_enabled = true
  labels                          = var.default_labels
}

# Sub-folders inside the AW-managed CONSUMER_FOLDER
# These reference module.frh.consumer_folder_id — a module output that carries
# an explicit dependency on the workload resource, fixing destroy ordering.
resource "google_folder" "networking" {
  display_name        = "${local.prefix}networking"
  parent              = module.frh.consumer_folder_id
  deletion_protection = var.deletion_protection
}

resource "google_folder" "security" {
  display_name        = "${local.prefix}security"
  parent              = module.frh.consumer_folder_id
  deletion_protection = var.deletion_protection
}

resource "google_folder" "shared_services" {
  display_name        = "${local.prefix}shared-services"
  parent              = module.frh.consumer_folder_id
  deletion_protection = var.deletion_protection
}

resource "google_folder" "workloads" {
  display_name        = "${local.prefix}workloads"
  parent              = module.frh.consumer_folder_id
  deletion_protection = var.deletion_protection
}

# Core projects inside the AW-managed folder
resource "google_project" "iac_core" {
  name            = "${local.prefix}iac-core"
  project_id      = "${local.prefix}iac-core"
  folder_id       = module.frh.consumer_folder_id
  billing_account = var.billing_account
  deletion_policy = var.deletion_protection ? "PREVENT" : "DELETE"
}

resource "google_project" "billing_core" {
  name            = "${local.prefix}billing-core"
  project_id      = "${local.prefix}billing-core"
  folder_id       = module.frh.consumer_folder_id
  billing_account = var.billing_account
  deletion_policy = var.deletion_protection ? "PREVENT" : "DELETE"
}

resource "google_project" "log_core" {
  name            = "${local.prefix}log-core"
  project_id      = "${local.prefix}log-core"
  folder_id       = module.frh.consumer_folder_id
  billing_account = var.billing_account
  deletion_policy = var.deletion_protection ? "PREVENT" : "DELETE"
}
