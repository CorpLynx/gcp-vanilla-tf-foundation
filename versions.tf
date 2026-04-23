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

  # NOTE: The Terraform Cloud backend block does not support variable interpolation.
  # Replace the placeholder values below with your actual TFC organization and workspace names,
  # or override them at init time with:
  #   terraform init \
  #     -backend-config="organization=<your-tfc-org>" \
  #     -backend-config="workspaces.name=<your-workspace>"
  cloud {
    # TODO: replace with your Terraform Cloud organization name
    organization = ""

    workspaces {
      # TODO: replace with your Terraform Cloud workspace name
      name = ""
    }
  }
}
