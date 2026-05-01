# Authoritative bindings — replaces all members for the given role
resource "google_folder_iam_binding" "authoritative" {
  for_each = var.iam
  folder   = google_folder.folder.id
  role     = each.key
  members  = each.value

  dynamic "condition" {
    for_each = try(var.iam_conditions[each.key], null) != null ? [var.iam_conditions[each.key]] : []
    content {
      title       = condition.value.title
      description = try(condition.value.description, null)
      expression  = condition.value.expression
    }
  }
}

# Additive bindings — adds members without replacing existing ones
resource "google_folder_iam_member" "additive" {
  for_each = var.iam_members
  folder   = google_folder.folder.id
  role     = each.value.role
  member   = each.value.member

  dynamic "condition" {
    for_each = try(each.value.condition, null) != null ? [each.value.condition] : []
    content {
      title       = condition.value.title
      description = try(condition.value.description, null)
      expression  = condition.value.expression
    }
  }
}
