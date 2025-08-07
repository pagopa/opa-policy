package azure.pagopa.opa.terraform.version

import input as tfplan
import rego.v1

# METADATA
# title: Minimum Terraform Version
# description: Minimum Terraform version must be 1.9.0
# custom:
#  severity: MEDIUM
#  package_string: azure.pagopa.opa.terraform.version
#  label: pagoPa-OPA

deny contains {
		sprintf("%s | %s %s: '%s' Minimum is '%s'", [annotation.custom.package_string, annotation.custom.label, annotation.description, v, minimum_terraform])
} if {
    annotation := rego.metadata.rule()
    v := tfplan.terraform_version
    semver.compare(v, minimum_terraform) < 0
	
}
minimum_terraform := "1.9.8"
