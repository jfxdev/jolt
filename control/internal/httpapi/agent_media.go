package httpapi

import (
	"mime"
	"net/http"
	"strings"
)

func agentFileResource(resource, action string) bool {
	parts := strings.Split(strings.Trim(resource, "/"), "/")
	return len(parts) == 4 && parts[0] == "mounts" && parts[2] == "files" && parts[3] == action
}

func agentAllowsMediaType(limits []string, contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "multipart/byteranges" {
		return false
	}
	for _, allowed := range limits {
		if allowed == strings.ToLower(mediaType) {
			return true
		}
	}
	return false
}

func refuseRestrictedAgentArchive(w http.ResponseWriter, r *http.Request, resource string) bool {
	agent, ok := r.Context().Value(agentKey).(agentContext)
	if !ok || len(agent.limits.ReadMediaTypes) == 0 || !agentFileResource(resource, "archive") {
		return false
	}
	writeError(w, r, http.StatusForbidden, "agent_archive_media_unsupported", "Downloads compactados estão indisponíveis quando a credencial restringe formatos de leitura.")
	return true
}

func authorizeAgentResponseMedia(w http.ResponseWriter, r *http.Request, resource string, response *http.Response) bool {
	agent, ok := r.Context().Value(agentKey).(agentContext)
	if !ok || len(agent.limits.ReadMediaTypes) == 0 || !agentFileResource(resource, "content") || response.StatusCode < 200 || response.StatusCode >= 300 {
		return true
	}
	if !agentAllowsMediaType(agent.limits.ReadMediaTypes, response.Header.Get("Content-Type")) {
		writeError(w, r, http.StatusForbidden, "agent_media_type_denied", "Este formato de leitura não é permitido para a credencial.")
		return false
	}
	return true
}
