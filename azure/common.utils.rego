package utils

# Checks if action is create or update
# Common path: resource.change.actions
is_create_or_update(change_actions) if {
	change_actions[count(change_actions) - 1] == ["create", "update"][_]
}

# Returns true when the resource is a managed resource of the expected type
# that is being created or updated.
is_in_scope(resource, type) if {
	resource.mode == "managed"
	is_create_or_update(resource.change.actions)
	resource.type == type
}
