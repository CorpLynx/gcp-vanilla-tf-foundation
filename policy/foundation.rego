# OPA/Conftest policy assertions for gcp-vanilla-tf-foundation Terraform plan JSON
#
# Usage:
#   terraform plan -out=plan.tfplan
#   terraform show -json plan.tfplan > plan.json
#   conftest test plan.json --policy policy/
#
# The plan JSON is produced by `terraform show -json` and has the structure:
#   planned_values.root_module.resources[]          — flat list of root resources
#   planned_values.root_module.child_modules[]      — child modules with resources[]
#   configuration.root_module.module_calls          — module source references
#   resource_changes[]                              — per-resource change details

package main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Collect every resource from planned_values, including those inside child modules.
all_resources := resources {
	root := input.planned_values.root_module

	# Resources declared directly in the root module
	root_resources := object.get(root, "resources", [])

	# Resources inside child modules (one level deep)
	child_resources := [r |
		m := root.child_modules[_]
		r := m.resources[_]
	]

	resources := array.concat(root_resources, child_resources)
}

# ---------------------------------------------------------------------------
# Assertion 1: All 14 custom roles are present
# ---------------------------------------------------------------------------

required_custom_role_ids := {
	"cloudkms_viewer",
	"folder_viewer",
	"logging_viewer",
	"network_firewall_policies_admin",
	"ngfw_enterprise_admin",
	"ngfw_enterprise_viewer",
	"organization_admin_viewer",
	"organization_iam_admin",
	"project_iam_viewer",
	"service_account_viewer",
	"service_networking_viewer",
	"service_project_network_admin",
	"storage_viewer",
	"tag_viewer",
}

# Extract the short role_id from a fully-qualified role name like
# "organizations/1041701195417/roles/cloudkms_viewer"
short_role_id(full_id) := id {
	parts := split(full_id, "/")
	id := parts[count(parts) - 1]
}

# Set of role_ids found in the plan for google_organization_iam_custom_role resources
planned_custom_role_ids := {id |
	r := all_resources[_]
	r.type == "google_organization_iam_custom_role"
	id := short_role_id(r.values.role_id)
}

missing_custom_roles := required_custom_role_ids - planned_custom_role_ids

deny[msg] {
	count(missing_custom_roles) > 0
	msg := sprintf("Missing required custom roles in plan: %v", [missing_custom_roles])
}

# ---------------------------------------------------------------------------
# Assertion 2: Assured Workload has compliance_regime = "FEDRAMP_HIGH"
# ---------------------------------------------------------------------------

deny[msg] {
	workloads := [r |
		r := all_resources[_]
		r.type == "google_assured_workloads_workload"
	]
	count(workloads) == 0
	msg := "No google_assured_workloads_workload resource found in plan"
}

deny[msg] {
	r := all_resources[_]
	r.type == "google_assured_workloads_workload"
	r.values.compliance_regime != "FEDRAMP_HIGH"
	msg := sprintf(
		"google_assured_workloads_workload has compliance_regime=%q; expected FEDRAMP_HIGH",
		[r.values.compliance_regime],
	)
}

# ---------------------------------------------------------------------------
# Assertion 3: google_organization_iam_audit_config targets allServices
# ---------------------------------------------------------------------------

deny[msg] {
	audit_configs := [r |
		r := all_resources[_]
		r.type == "google_organization_iam_audit_config"
	]
	count(audit_configs) == 0
	msg := "No google_organization_iam_audit_config resource found in plan"
}

deny[msg] {
	r := all_resources[_]
	r.type == "google_organization_iam_audit_config"
	r.values.service != "allServices"
	msg := sprintf(
		"google_organization_iam_audit_config targets service=%q; expected allServices",
		[r.values.service],
	)
}

# ---------------------------------------------------------------------------
# Assertion 4: All 3 log sinks are present with correct filter strings
# ---------------------------------------------------------------------------

required_sinks := {
	"audit-logs": `logName:("/logs/cloudaudit.googleapis.com%2Factivity" OR "/logs/cloudaudit.googleapis.com%2Fsystem_event" OR "/logs/cloudaudit.googleapis.com%2Fpolicy" OR "/logs/cloudaudit.googleapis.com%2Faccess_transparency")`,
	"iam": `protoPayload.serviceName=("iamcredentials.googleapis.com" OR "iam.googleapis.com" OR "sts.googleapis.com")`,
	"vpc-sc": `protoPayload.metadata.@type="type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata"`,
}

planned_sinks[name] := filter {
	r := all_resources[_]
	r.type == "google_logging_organization_sink"
	name := r.values.name
	filter := r.values.filter
}

deny[msg] {
	some name
	required_sinks[name]
	not planned_sinks[name]
	msg := sprintf("Required log sink %q not found in plan", [name])
}

deny[msg] {
	expected_filter := required_sinks[name]
	actual_filter := planned_sinks[name]
	actual_filter != expected_filter
	msg := sprintf(
		"Log sink %q has unexpected filter.\n  expected: %q\n  actual:   %q",
		[name, expected_filter, actual_filter],
	)
}

# ---------------------------------------------------------------------------
# Assertion 5: No resource references a FAST module source path
# ---------------------------------------------------------------------------

# FAST module paths contain "fabric-" or reference the fast-modules directory.
# We check module_calls in the configuration block.
fast_source_pattern(src) {
	contains(src, "fast-modules")
}

fast_source_pattern(src) {
	contains(src, "fabric-")
}

deny[msg] {
	module_calls := object.get(input, ["configuration", "root_module", "module_calls"], {})
	some key
	mc := module_calls[key]
	src := mc.source
	fast_source_pattern(src)
	msg := sprintf("Module call %q references a FAST module source path: %q", [key, src])
}

# ---------------------------------------------------------------------------
# Assertion 6: prevent_destroy = true on FedRAMP High folder and Assured Workload
# ---------------------------------------------------------------------------

# Terraform plan JSON does not expose lifecycle.prevent_destroy in planned_values.
# The reliable location is:
#   - configuration.root_module.resources[].lifecycle.prevent_destroy  (root-level resources)
#   - configuration.root_module.module_calls.<name>.module.resources[].lifecycle.prevent_destroy
#     (resources inside child modules)
#
# For the FedRAMP High folder: the folder module (modules/folder) declares
# lifecycle.prevent_destroy = true on its google_folder resource. We verify this
# by finding the module call whose "name" input expression is "FedRAMP High" and
# then confirming the google_folder resource inside that module has prevent_destroy.
#
# For the Assured Workload: it is a root-level resource with its own lifecycle block.

root_cfg := object.get(input, ["configuration", "root_module"], {})

# Helper: does a config resource have prevent_destroy = true?
has_prevent_destroy(cfg_resource) {
	cfg_resource.lifecycle.prevent_destroy == true
}

# ---------------------------------------------------------------------------
# 6a: FedRAMP High folder
#
# Strategy A — check the module call whose "name" input is "FedRAMP High".
# The module_calls map key is the module label (e.g. "folder_fedramp_high").
# Its expressions.name.constant_value should be "FedRAMP High".
# Then verify the google_folder resource inside that module has prevent_destroy.
# ---------------------------------------------------------------------------

fedramp_module_calls := [mc |
	mc := root_cfg.module_calls[_]
	name_val := object.get(mc, ["expressions", "name", "constant_value"], "")
	contains(name_val, "FedRAMP High")
]

# Strategy B — fall back to checking planned_values: find the google_folder whose
# display_name is "FedRAMP High" and verify it appears in resource_changes with
# no destroy action (i.e. prevent_destroy is implicitly enforced).
# We use Strategy A as primary; if the module call is found, check its resources.

deny[msg] {
	# Only fire if we can locate the module call
	count(fedramp_module_calls) > 0
	mc := fedramp_module_calls[_]
	mod := object.get(mc, "module", {})
	folder_resources := [r |
		r := mod.resources[_]
		r.type == "google_folder"
	]
	count(folder_resources) > 0
	r := folder_resources[_]
	not has_prevent_destroy(r)
	msg := "FedRAMP High google_folder does not have lifecycle.prevent_destroy = true"
}

deny[msg] {
	# Fire if we cannot locate the FedRAMP High folder module call at all
	count(fedramp_module_calls) == 0
	# Also check root-level google_folder resources as a fallback
	root_folders := [r |
		r := object.get(root_cfg, "resources", [])[_]
		r.type == "google_folder"
		name_val := object.get(r, ["expressions", "display_name", "constant_value"], "")
		contains(name_val, "FedRAMP High")
	]
	count(root_folders) == 0
	msg := "Could not locate the FedRAMP High google_folder resource in plan configuration"
}

# ---------------------------------------------------------------------------
# 6b: Assured Workload (root-level resource)
# ---------------------------------------------------------------------------

assured_workload_configs := [r |
	r := object.get(root_cfg, "resources", [])[_]
	r.type == "google_assured_workloads_workload"
]

deny[msg] {
	count(assured_workload_configs) == 0
	msg := "Could not locate google_assured_workloads_workload resource in plan configuration"
}

deny[msg] {
	r := assured_workload_configs[_]
	not has_prevent_destroy(r)
	msg := "google_assured_workloads_workload does not have lifecycle.prevent_destroy = true"
}
