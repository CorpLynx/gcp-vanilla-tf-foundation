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
provider "google" {
  impersonate_service_account = var.iac_sa_email
}

provider "google-beta" {
  impersonate_service_account = var.iac_sa_email
}

# Static top-level folders — stable org structure, named resources
resource "google_folder" "test" {
  display_name = "test"
  parent       = "organizations/${var.org.id}"
}
