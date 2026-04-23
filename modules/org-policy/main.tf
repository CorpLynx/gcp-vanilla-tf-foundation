resource "google_org_policy_custom_constraint" "constraint" {
  for_each = var.custom_constraints

  name           = each.key
  parent         = "organizations/${var.org_id}"
  resource_types = each.value.resource_types
  method_types   = each.value.method_types
  condition      = each.value.condition
  action_type    = each.value.action_type
  display_name   = each.value.display_name
  description    = each.value.description
}

resource "google_org_policy_policy" "policy" {
  for_each = var.policies

  name   = "organizations/${var.org_id}/policies/${each.key}"
  parent = "organizations/${var.org_id}"

  depends_on = [google_org_policy_custom_constraint.constraint]

  spec {
    dynamic "rules" {
      for_each = each.value.rules
      content {
        enforce = rules.value.enforce != null ? (rules.value.enforce ? "TRUE" : "FALSE") : null

        dynamic "values" {
          for_each = rules.value.values != null ? [rules.value.values] : []
          content {
            allowed_values = values.value.allow
            denied_values  = values.value.deny
          }
        }

        dynamic "condition" {
          for_each = rules.value.condition != null ? [rules.value.condition] : []
          content {
            title      = condition.value.title
            expression = condition.value.expression
          }
        }
      }
    }
  }
}
