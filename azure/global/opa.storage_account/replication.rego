package azure.global.opa.storage_account.replication

# METADATA
# title: Check Storage Account Replication
# description: Storage Accounts should be ZRS or GZRS
# custom:
#  severity: MEDIUM
#  package_string: azure.global.opa.storage_account.replication
#  label: pagoPa-OPA

deny contains {
		sprintf("%s | %s %s: '%s'", [annotation.custom.package_string, annotation.custom.label, annotation.description, resource.address])
} if {
	annotation := rego.metadata.rule()
	resource := input.resource_changes[_]
   	is_in_scope(resource, "azurerm_storage_account")
	not validzrs(resource)
	not validgzrs(resource)
	reason := sprintf("pagoPa-OPA: Storage Accounts should be ZRS or GZRS: '%s'", [resource.values.name])
}

is_in_scope(resource, type) if {
    resource.type == type
	data.utils.is_create_or_update(resource)
	
}

validzrs(resource) if {
	resource.values.account_replication_type == "LRS"
}
validgzrs(resource) if {
	resource.values.account_replication_type == "GLRS"
}

