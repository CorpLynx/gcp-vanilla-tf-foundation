# IAM on the service account itself (who can use/impersonate this SA)
resource "google_service_account_iam_binding" "authoritative" {
  for_each           = var.iam
  service_account_id = var.create ? google_service_account.sa[0].name : "projects/${var.project_id}/serviceAccounts/${local.sa_email}"
  role               = each.key
  members            = each.value
}

resource "google_service_account_iam_member" "additive" {
  for_each           = var.iam_members
  service_account_id = var.create ? google_service_account.sa[0].name : "projects/${var.project_id}/serviceAccounts/${local.sa_email}"
  role               = each.value.role
  member             = each.value.member
}

# Grant this SA roles on other resources
resource "google_project_iam_member" "project_roles" {
  for_each = {
    for pair in flatten([
      for project, roles in var.iam_project_roles : [
        for role in roles : { project = project, role = role }
      ]
    ]) : "${pair.project}-${pair.role}" => pair
  }
  project = each.value.project
  role    = each.value.role
  member  = local.iam_email
}

resource "google_folder_iam_member" "folder_roles" {
  for_each = {
    for pair in flatten([
      for folder, roles in var.iam_folder_roles : [
        for role in roles : { folder = folder, role = role }
      ]
    ]) : "${pair.folder}-${pair.role}" => pair
  }
  folder = each.value.folder
  role   = each.value.role
  member = local.iam_email
}

resource "google_organization_iam_member" "org_roles" {
  for_each = {
    for pair in flatten([
      for org, roles in var.iam_org_roles : [
        for role in roles : { org = org, role = role }
      ]
    ]) : "${pair.org}-${pair.role}" => pair
  }
  org_id = each.value.org
  role   = each.value.role
  member = local.iam_email
}
