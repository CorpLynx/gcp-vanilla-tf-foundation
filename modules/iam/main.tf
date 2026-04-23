resource "google_organization_iam_binding" "authoritative" {
  for_each = var.authoritative_bindings

  org_id  = trimprefix(var.resource_id, "organizations/")
  role    = each.key
  members = each.value
}

resource "google_organization_iam_member" "additive" {
  for_each = var.additive_bindings

  org_id = trimprefix(var.resource_id, "organizations/")
  role   = each.value.role
  member = each.value.member
}
