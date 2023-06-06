package etpx
import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

allow if {
	input.resource in actionable_resources
}

user_policies contains policy if {
	some subject in graph.reachable(data.subjects, {input.subject})
    policies := {policy | policy := data.policies[subject][_]}
    policies[policy]
}

actionable_policies contains policy if {
	some policy in user_policies
    input.action in graph.reachable(data.actions, {policy.action})
}

actionable_resources contains resource if {
	some policy in actionable_policies
    some resource in graph.reachable(data.resources, {policy.resource})
    not startswith(resource, "/")
}

resource_actions contains action if {
    some policy in user_policies
    some resource in graph.reachable(data.resources, {policy.resource})
    resource == input.resource
    some action in graph.reachable(data.actions, {policy.action})
    not startswith(action, "/")
}

subject_permissions := permissions {
    permissions := {}
    some policy in user_policies
    some resource in graph.reachable(data.resources, {policy.resource})
    not startswith(resource, "/")
    actions := { action | 
        some action in graph.reachable(data.actions, {policy.action})
        not startswith(action, "/")
    }
    permissions[resource] := actions
}