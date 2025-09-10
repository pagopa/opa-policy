package azure.pagopa.opa.terraform.location

import input as tfplan


# METADATA
# title: Check deployment resource location
# description: location is NOT allowed
# custom:
#  severity: MEDIUM
#  package_string: azure.pagopa.opa.terraform.location
#  label: pagoPa-OPA

deny contains {
		sprintf("%s | %s: '%s' %s '%s'", [annotation.custom.package_string, annotation.custom.label, location, annotation.description, resource.address])
} if {
    annotation := rego.metadata.rule()
    resource := tfplan.resource_changes[_]
    location := get_location(resource, tfplan)
    provider_name := get_basename(resource.provider_name)
    not array_contains(allowed_locations[provider_name], location)
}

allowed_locations = {
    "azurerm": ["westeurope", "northeurope", "italynorth", "germanywestcentral", "global", "autoresolve"]
}


array_contains(arr, elem) if {
  arr[_] = elem
}

get_basename(path) = basename if {
    arr := split(path, "/")
    basename:= arr[count(arr)-1]
}

eval_expression(plan, expr) = constant_value if {
    constant_value := expr.constant_value
} else = reference if {
    ref = expr.references[0]
    startswith(ref, "var.")
    var_name := replace(ref, "var.", "")
    reference := plan.variables[var_name].value
}

get_location(resource, plan) = azure_location if {
    provider_name := get_basename(resource.provider_name)
    "azurerm" == provider_name
    azure_location := resource.change.after.location
} 
