package mcpserver

import "net/http"

// act is one action of a group tool.
func act(name, summary string, kind toolKind, method, path string, params ...param) groupAction {
	return groupAction{name: name, route: routeTool{name: name, description: summary, kind: kind, method: method, path: path, params: params}}
}

func listAction(name, path string, params ...param) groupAction {
	return act(name, "", kindRead, http.MethodGet, path, params...)
}

func idsParam(field string) param {
	return param{name: field, typ: typeStrings, in: inBody, required: true}
}

// adminGroups manage identities, policies and the fleet. They are opt-in, and
// routes that rotate keys, certificates or node credentials are left to the
// UI: a mistake there cuts nodes off. Each resource is one tool: an agent
// that loads the admin toolset pays for a dozen schemas, not seventy.
func adminGroups() []groupTool {
	group := func(name, description string, actions ...groupAction) groupTool {
		return groupTool{toolset: ToolsetAdmin, name: name, description: description, actions: actions}
	}
	user, account, groupID := pathID("user_id"), pathID("service_account_id"), pathID("group_id")
	policy, role, token := pathID("policy_id"), pathID("role_id"), pathID("token_id")
	share, request := pathID("share_id"), pathID("request_id")
	note := param{name: "note", typ: typeString, in: inBody}
	grant := []param{
		{name: "policy_id", typ: typeID, in: inBody, required: true},
		{name: "duration_seconds", typ: typeInteger, in: inBody},
	}
	users := controlAPI + "/users/"
	accounts := controlAPI + "/service-accounts/"
	groups := controlAPI + "/access-groups/"
	enrollments := controlAPI + "/enrollments/"
	connections := controlAPI + "/connections/"
	return []groupTool{
		group("manage_users", "Users and what they may do. assign_* replaces the whole set.",
			listAction("list", controlAPI+"/users"),
			act("create", "", kindWrite, http.MethodPost, controlAPI+"/users", body("{username,password,role,enabled}")),
			act("update", "only given fields change", kindWrite, http.MethodPatch, users+"{user_id}", user, body("{username,password,role,enabled}")),
			act("delete", "", kindDestructive, http.MethodDelete, users+"{user_id}", user),
			listAction("list_policies", users+"{user_id}/policies", user),
			act("assign_policies", "", kindDestructive, http.MethodPut, users+"{user_id}/policies", user, idsParam("policy_ids")),
			listAction("list_roles", users+"{user_id}/roles", user),
			act("assign_roles", "", kindDestructive, http.MethodPut, users+"{user_id}/roles", user, idsParam("role_ids")),
			listAction("list_temporary_policies", users+"{user_id}/policies/temporary", user),
			act("grant_temporary_policy", "900 s unless duration_seconds", kindWrite, http.MethodPost, users+"{user_id}/policies/temporary", append([]param{user}, grant...)...),
			act("revoke_temporary_policy", "", kindDestructive, http.MethodDelete, users+"{user_id}/policies/temporary/{policy_id}", user, policy),
		),
		group("manage_service_accounts", "Service accounts (agents, automations), their tokens, groups, policies and workload identities. Token secrets are returned once, on creation.",
			listAction("list", controlAPI+"/service-accounts"),
			act("create", "token_name also issues a token", kindWrite, http.MethodPost, controlAPI+"/service-accounts",
				body("{kind,name,description,group_ids,enabled,token_name,expires_at,agent_limits}")),
			act("update", "", kindWrite, http.MethodPatch, accounts+"{service_account_id}", account, body("{name,description,enabled}")),
			act("delete", "also its tokens", kindDestructive, http.MethodDelete, accounts+"{service_account_id}", account),
			act("disable_agents", "emergency stop of every agent", kindDestructive, http.MethodPost, controlAPI+"/service-accounts/disable"),
			listAction("list_tokens", accounts+"{service_account_id}/tokens", account),
			act("create_token", "", kindWrite, http.MethodPost, accounts+"{service_account_id}/tokens", account, body("{name,expires_at,revoke_existing,agent_limits}")),
			act("update_token", "", kindWrite, http.MethodPatch, accounts+"{service_account_id}/tokens/{token_id}", account, token, body("{name,agent_limits}")),
			act("revoke_token", "", kindDestructive, http.MethodDelete, accounts+"{service_account_id}/tokens/{token_id}", account, token),
			listAction("list_groups", accounts+"{service_account_id}/groups", account),
			act("assign_groups", "", kindDestructive, http.MethodPut, accounts+"{service_account_id}/groups", account, idsParam("ids")),
			listAction("list_policies", accounts+"{service_account_id}/policies", account),
			act("assign_policies", "", kindDestructive, http.MethodPut, accounts+"{service_account_id}/policies", account, idsParam("policy_ids")),
			listAction("list_temporary_policies", accounts+"{service_account_id}/policies/temporary", account),
			act("grant_temporary_policy", "900 s unless duration_seconds", kindWrite, http.MethodPost, accounts+"{service_account_id}/policies/temporary", append([]param{account}, grant...)...),
			act("revoke_temporary_policy", "", kindDestructive, http.MethodDelete, accounts+"{service_account_id}/policies/temporary/{policy_id}", account, policy),
			listAction("list_workload_identities", accounts+"{service_account_id}/workload-identities", account),
			act("create_workload_identity", "", kindWrite, http.MethodPost, accounts+"{service_account_id}/workload-identities", account, body("")),
			act("update_workload_identity", "", kindWrite, http.MethodPatch, accounts+"{service_account_id}/workload-identities/{credential_id}", account, pathID("credential_id"), body("")),
		),
		group("manage_access_groups", "Access groups: the nodes and policies a set of service accounts gets. assign_* replaces the whole set.",
			listAction("list", controlAPI+"/access-groups"),
			act("create", "", kindWrite, http.MethodPost, controlAPI+"/access-groups", body("{name,description,enabled}")),
			act("update", "", kindWrite, http.MethodPatch, groups+"{group_id}", groupID, body("{name,description,enabled}")),
			act("delete", "", kindDestructive, http.MethodDelete, groups+"{group_id}", groupID),
			listAction("list_nodes", groups+"{group_id}/nodes", groupID),
			act("assign_nodes", "", kindDestructive, http.MethodPut, groups+"{group_id}/nodes", groupID, idsParam("ids")),
			listAction("list_policies", groups+"{group_id}/policies", groupID),
			act("assign_policies", "", kindDestructive, http.MethodPut, groups+"{group_id}/policies", groupID, idsParam("ids")),
		),
		group("manage_policies", "Policies (path rules with capabilities) and roles (named sets of policies).",
			listAction("list", controlAPI+"/policies"),
			act("create", "", kindWrite, http.MethodPost, controlAPI+"/policies", body("{name,description,rules:[{path,capabilities}]}")),
			act("update", "", kindDestructive, http.MethodPatch, controlAPI+"/policies/{policy_id}", policy, body("{name,description,rules}")),
			act("delete", "", kindDestructive, http.MethodDelete, controlAPI+"/policies/{policy_id}", policy),
			listAction("list_roles", controlAPI+"/roles"),
			act("create_role", "", kindWrite, http.MethodPost, controlAPI+"/roles", body("{name,description,policy_ids}")),
			act("update_role", "", kindDestructive, http.MethodPatch, controlAPI+"/roles/{role_id}", role, body("{name,description,policy_ids}")),
			act("delete_role", "", kindDestructive, http.MethodDelete, controlAPI+"/roles/{role_id}", role),
		),
		group("manage_shares", "Public share links to files and directories.",
			listAction("list", controlAPI+"/shares"),
			act("create", "", kindWrite, http.MethodPost, controlAPI+"/shares", body("{node_id,mount_id,path,kind,password,allow_archive,max_downloads,expires_in_seconds}")),
			act("revoke", "keeps the record", kindDestructive, http.MethodPost, controlAPI+"/shares/{share_id}/revoke", share),
			act("delete", "", kindDestructive, http.MethodDelete, controlAPI+"/shares/{share_id}", share),
		),
		group("manage_mounts", "Mounts of a node. delete keeps the files on disk.",
			act("browse_host_fs", "absolute path on the node, to pick a mount root", kindRead, http.MethodGet, nodeAPI+"/fs/browse", nodeParam,
				param{name: "path", typ: typeString, in: inQuery}),
			act("create", "", kindWrite, http.MethodPost, nodeAPI+"/mounts", nodeParam, body("shape of get_mount")),
			act("update", "replaces the configuration", kindDestructive, http.MethodPut, mountAPI, nodeParam, mountParam, body("shape of get_mount")),
			act("delete", "", kindDestructive, http.MethodDelete, mountAPI, nodeParam, mountParam),
		),
		group("manage_nodes", "Node registration and enrollment. Join token secrets are returned once.",
			act("create", "", kindWrite, http.MethodPost, controlAPI+"/nodes", body("{name,endpoint,token}")),
			act("delete", "", kindDestructive, http.MethodDelete, controlAPI+"/nodes/{node_id}", nodeParam),
			listAction("list_enrollments", controlAPI+"/enrollments"),
			act("approve_enrollment", "", kindWrite, http.MethodPost, enrollments+"{enrollment_id}/approve", pathID("enrollment_id"), note),
			act("reject_enrollment", "", kindWrite, http.MethodPost, enrollments+"{enrollment_id}/reject", pathID("enrollment_id"), note),
			listAction("list_join_tokens", controlAPI+"/enrollments/tokens"),
			act("create_join_token", "", kindWrite, http.MethodPost, controlAPI+"/enrollments/tokens", body("{node_name,approval,valid_minutes}")),
			act("revoke_join_token", "", kindDestructive, http.MethodDelete, controlAPI+"/enrollments/tokens/{token_id}", token),
		),
		group("manage_peering", "Connections between nodes, the grants a node offers its peers, and peers.",
			act("create_connection", "", kindWrite, http.MethodPost, controlAPI+"/connections",
				body("{issuer_node_id,target_node_id,transfer_mode,issuer_role,invitee_role,purpose,cluster_id,expiry_minutes}")),
			act("approve_connection", "", kindWrite, http.MethodPost, connections+"{request_id}/approve", request,
				param{name: "confirmed_fingerprint", typ: typeString, in: inBody}),
			act("reject_connection", "", kindWrite, http.MethodPost, connections+"{request_id}/reject", request),
			act("revoke_connection", "", kindDestructive, http.MethodPost, connections+"{request_id}/revoke", request),
			act("reconcile_connection", "retry applying it to both nodes", kindWrite, http.MethodPost, connections+"{request_id}/reconcile", request),
			act("create_grant", "", kindWrite, http.MethodPost, nodeAPI+"/grants", nodeParam, body("shape of list_grants")),
			act("update_grant", "", kindDestructive, http.MethodPatch, nodeAPI+"/grants/{grant_id}", nodeParam, pathID("grant_id"), body("")),
			act("revoke_peer", "unpair", kindDestructive, http.MethodDelete, nodeAPI+"/peers/{peer_node_id}", nodeParam, pathID("peer_node_id")),
		),
	}
}
