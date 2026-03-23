# METADATA
# title: Check Network Security Group destination port
# description: NSG security rules must not use wildcard '*' as destination port range
# scope: package
# custom:
#  severity: HIGH
#  package_string: azure.global.opa.network_security_group.destination_port
#  label: pagoPa-OPA

package azure.global.opa.network_security_group.destination_port

import input as tfplan
import rego.v1

# Deny rule for azurerm_network_security_group resources with inline security_rule blocks.
# Iterates over every inline rule and flags any that use the bare wildcard as destination port.
deny contains {
	sprintf("%s | %s %s: '%s'", [annotation.custom.package_string, annotation.custom.label, annotation.description, resource.address])
} if {
	chain := rego.metadata.chain()
	annotation := chain[count(chain) - 1].annotations
	resource := tfplan.resource_changes[_]
	is_in_scope(resource, "azurerm_network_security_group")
	security_rule := resource.change.after.security_rule[_]
	is_wildcard_port(security_rule.destination_port_range)
}

# Deny rule for standalone azurerm_network_security_rule resources.
# Flags any resource whose destination_port_range is set to the bare wildcard.
deny contains {
	sprintf("%s | %s %s: '%s'", [annotation.custom.package_string, annotation.custom.label, annotation.description, resource.address])
} if {
	chain := rego.metadata.chain()
	annotation := chain[count(chain) - 1].annotations
	resource := tfplan.resource_changes[_]
	is_in_scope(resource, "azurerm_network_security_rule")
	is_wildcard_port(resource.change.after.destination_port_range)
}

# Helper: returns true when the resource is a managed resource of the expected type
# that is being created or updated.
is_in_scope(resource, type) if {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == type
}

# Helper: returns true when the given port range is the bare wildcard "*".
# Explicit ports (e.g. "443"), ranges (e.g. "80-443"), and comma-separated
# values are all valid and will NOT trigger a violation.
is_wildcard_port(port_range) if {
	port_range == "*"
}
