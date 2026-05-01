# Authoritative bindings — replaces all members for the given role at org level
resource "google_organization_iam_binding" "authoritative" {
  for_each = var.iam
  org_id   = var.org_id
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

# Additive bindings
resource "google_organization_iam_member" "additive" {
  for_each = var.iam_members
  org_id   = var.org_id
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

# Custom roles at org level
resource "google_organization_iam_custom_role" "roles" {
  for_each    = var.custom_roles
  org_id      = var.org_id
  role_id     = each.key
  title       = each.value.title
  description = try(each.value.description, null)
  permissions = each.value.permissions
  stage       = try(each.value.stage, "GA")
}

# Org policies (v2 API)
resource "google_org_policy_policy" "default" {
  for_each = var.org_policies
  name     = "organizations/${var.org_id}/policies/${each.key}"
  parent   = "organizations/${var.org_id}"

  spec {
    inherit_from_parent = try(each.value.inherit_from_parent, null)
    reset               = try(each.value.reset, null)

    dynamic "rules" {
      for_each = try(each.value.rules, [])
      content {
        deny_all  = try(rules.value.deny_all, null)
        allow_all = try(rules.value.allow_all, null)
        enforce   = try(rules.value.enforce, null)

        dynamic "condition" {
          for_each = try(rules.value.condition, null) != null ? [rules.value.condition] : []
          content {
            description = try(condition.value.description, null)
            expression  = try(condition.value.expression, null)
            location    = try(condition.value.location, null)
            title       = try(condition.value.title, null)
          }
        }

        dynamic "values" {
          for_each = try(rules.value.values, null) != null ? [rules.value.values] : []
          content {
            allowed_values = try(values.value.allowed_values, null)
            denied_values  = try(values.value.denied_values, null)
          }
        }
      }
    }
  }
}
