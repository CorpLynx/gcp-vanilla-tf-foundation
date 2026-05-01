resource "google_project_iam_binding" "authoritative" {
  for_each = var.iam
  project  = google_project.project.project_id
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

resource "google_project_iam_member" "additive" {
  for_each = var.iam_members
  project  = google_project.project.project_id
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
