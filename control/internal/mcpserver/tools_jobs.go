package mcpserver

import "net/http"

var conflictPolicies = []string{"skip", "overwrite", "rename", "fail", "checksum"}

func fileWriteRoutes() []routeTool {
	route := func(name, description string, kind toolKind, method, path string, params ...param) routeTool {
		return routeTool{toolset: ToolsetFilesWrite, name: name, description: description, kind: kind, method: method, path: path, params: params}
	}
	files := mountAPI + "/files"
	source := param{name: "source_path", typ: typePath, in: inBody, required: true}
	destination := param{name: "destination_path", typ: typePath, in: inBody, required: true}
	conflict := param{name: "conflict_policy", typ: typeString, in: inBody, enum: conflictPolicies}
	checksum := param{name: "verify_checksum", typ: typeBoolean, in: inBody}
	overwrite := param{name: "overwrite", typ: typeBoolean, in: inBody}
	trash := pathID("trash_id")
	return []routeTool{
		route("mkdir", "Create a directory.", kindWrite, http.MethodPost, files+"/directories", nodeParam, mountParam,
			param{name: "path", typ: typePath, in: inBody, required: true}),
		route("plan_copy", "Preview a copy within a mount; changes nothing.", kindRead, http.MethodPost, files+"/copy/plan",
			nodeParam, mountParam, source, destination, conflict, checksum),
		route("copy", "Copy within a mount.", kindWrite, http.MethodPost, files+"/copy", nodeParam, mountParam, source, destination, conflict, checksum),
		route("move", "Move or rename within a mount.", kindDestructive, http.MethodPost, files+"/move", nodeParam, mountParam, source, destination, overwrite),
		route("delete", "Delete; goes to trash when enabled. recursive for non-empty directories.", kindDestructive, http.MethodDelete, files, nodeParam, mountParam,
			param{name: "path", typ: typePath, in: inQuery, required: true},
			param{name: "recursive", typ: typeBoolean, in: inQuery}),
		route("plan_destructive", "Plan deleting or moving a directory tree (needed on plan_required). Returns plan_id, token and the files and bytes affected: show them to the user before confirm_destructive.",
			kindWrite, http.MethodPost, files+"/destructive-plans", nodeParam, mountParam,
			param{name: "operation", typ: typeString, in: inBody, required: true, enum: []string{"delete", "move"}},
			param{name: "source_path", typ: typePath, in: inBody, required: true},
			param{name: "destination_path", typ: typePath, in: inBody},
			overwrite),
		route("confirm_destructive", "Run a plan_destructive plan; refused if the tree changed.", kindDestructive, http.MethodPost, files+"/destructive-plans/{plan_id}/confirm",
			nodeParam, mountParam, pathID("plan_id"), param{name: "token", typ: typeString, in: inBody, required: true}),
		route("restore_trash", "Restore a trash entry.", kindWrite, http.MethodPost, mountAPI+"/trash/{trash_id}/restore", nodeParam, mountParam, trash),
		route("purge_trash", "Delete a trash entry for good.", kindDestructive, http.MethodDelete, mountAPI+"/trash/{trash_id}", nodeParam, mountParam, trash),
	}
}

func jobRoutes() []routeTool {
	route := func(name, description string, kind toolKind, path string, params ...param) routeTool {
		return routeTool{toolset: ToolsetJobs, name: name, description: description, kind: kind, method: http.MethodPost, path: path, params: params}
	}
	operation := param{name: "operation", typ: typeString, in: inBody, required: true, enum: []string{"copy", "move"}}
	source := param{name: "source", typ: typeObject, in: inBody, required: true, description: "{node_id,mount_id,paths}"}
	transfer := []param{
		pathID("node_id"), operation, source,
		{name: "destination", typ: typeObject, in: inBody, required: true, description: "{mount_id,path}"},
		{name: "conflict_policy", typ: typeString, in: inBody, enum: conflictPolicies},
		{name: "verify_checksum", typ: typeBoolean, in: inBody},
		{name: "bandwidth_limit_bytes_per_second", typ: typeInteger, in: inBody},
		{name: "move_plan", typ: typeObject, in: inBody, description: "{plan_id,token} from plan_transfer; required for a move"},
	}
	return []routeTool{
		route("override_job_item", "Decide a job item waiting on a conflict.", kindDestructive, nodeAPI+"/jobs/{job_id}/items/{ordinal}/override",
			nodeParam, jobParam, pathID("ordinal"),
			param{name: "action", typ: typeString, in: inBody, required: true, enum: []string{"skip", "overwrite", "rename", "fail"}},
			param{name: "apply_to_following", typ: typeBoolean, in: inBody}),
		route("transfer_targets", "Nodes and mounts a selection can be copied or moved to. node_id is the source.", kindRead, nodeAPI+"/transfers/targets",
			pathID("node_id"), operation, source),
		route("plan_transfer", "Preview a transfer between nodes. node_id is the destination.", kindRead, nodeAPI+"/transfers/plan", transfer...),
		route("create_transfer", "Copy or move between nodes. node_id is the destination.", kindDestructive, nodeAPI+"/transfers", transfer...),
	}
}

func jobGroups() []groupTool {
	job := func(name, summary string, kind toolKind) groupAction {
		return act(name, summary, kind, http.MethodPost, nodeAPI+"/jobs/{job_id}/"+name, nodeParam, jobParam)
	}
	operation := pathID("operation_id")
	return []groupTool{
		{toolset: ToolsetJobs, name: "control_job", description: "Change a job's state.", actions: []groupAction{
			job("pause", "", kindWrite),
			job("resume", "", kindWrite),
			job("cancel", "done work stays", kindDestructive),
			job("retry", "a failed job", kindWrite),
		}},
		{toolset: ToolsetJobs, name: "decide_pending_operation", description: "Approve (it then runs) or reject an operation waiting for approval.", actions: []groupAction{
			act("approve", "acknowledge_self_approval to approve one's own request", kindDestructive, http.MethodPost, controlAPI+"/pending-operations/{operation_id}/approve", operation,
				param{name: "acknowledge_self_approval", typ: typeBoolean, in: inBody}),
			act("reject", "", kindWrite, http.MethodPost, controlAPI+"/pending-operations/{operation_id}/reject", operation,
				param{name: "note", typ: typeString, in: inBody}),
		}},
	}
}
