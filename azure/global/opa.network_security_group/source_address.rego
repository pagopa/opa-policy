# METADATA
# title: Check Network Security Group source address wildcard
# description: NSG Allow rules must not use wildcard '*' as source address prefix
# scope: package
# custom:
#  severity: HIGH
#  package_string: azure.global.opa.network_security_group.source_address
#  label: pagoPa-OPA

package azure.global.opa.network_security_group.source_address

import input as tfplan
import rego.v1

# Deny inline Allow rules on azurerm_network_security_group with wildcard source address.
# Iterates each inline security_rule block independently so a single bad rule triggers exactly
# one violation, regardless of how many rules the NSG contains.
deny contains {
	sprintf("%s | %s %s: '%s'", [annotation.custom.package_string, annotation.custom.label, annotation.description, resource.address])
} if {
	chain := rego.metadata.chain()
	annotation := chain[count(chain) - 1].annotations
	resource := tfplan.resource_changes[_]
	is_in_scope(resource, "azurerm_network_security_group")
	security_rule := resource.change.after.security_rule[_]
	security_rule.access == "Allow"
	is_wildcard_address(security_rule.source_address_prefix)
}

# Deny standalone azurerm_network_security_rule Allow rules with wildcard source address.
deny contains {
	sprintf("%s | %s %s: '%s'", [annotation.custom.package_string, annotation.custom.label, annotation.description, resource.address])
} if {
	chain := rego.metadata.chain()
	annotation := chain[count(chain) - 1].annotations
	resource := tfplan.resource_changes[_]
	is_in_scope(resource, "azurerm_network_security_rule")
	resource.change.after.access == "Allow"
	is_wildcard_address(resource.change.after.source_address_prefix)
}

# Helper: returns true when the resource is a managed resource of the expected type
# that is being created or updated.
is_in_scope(resource, type) if {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == type
}

# Helper: returns true when the given source address prefix is the bare wildcard "*".
# Specific CIDRs (e.g. "10.0.0.0/8"), service tags (e.g. "VirtualNetwork", "AzureLoadBalancer"),
# and IP addresses are all valid and will NOT trigger a violation.
is_wildcard_address(address_prefix) if {
	address_prefix == "*"
}
