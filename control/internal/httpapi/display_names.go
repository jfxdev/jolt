package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
)

var errListingTooLarge = errors.New("listing exceeds limit")

// displayName neutralizes terminal and bidirectional controls without changing
// the canonical name or path required to navigate to the entry.
func displayName(name string) string {
	var out strings.Builder
	count := 0
	for _, r := range name {
		if count == 255 {
			out.WriteString("…")
			break
		}
		count++
		if unicode.IsControl(r) || r == '\u061c' || r == '\u200e' || r == '\u200f' ||
			r == '\u2028' || r == '\u2029' || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u206f' {
			fmt.Fprintf(&out, "⟦U+%04X⟧", r)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

// decorateAgentEntries buffers only a bounded listing, verifies the node
// respected the result limit, and adds a presentation-only field.
func decorateAgentEntries(body io.Reader, key string, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errListingTooLarge
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(data, &response); err != nil || response == nil {
		return nil, errors.New("invalid listing")
	}
	var entries []json.RawMessage
	if raw, ok := response[key]; !ok || json.Unmarshal(raw, &entries) != nil || entries == nil || len(entries) > 200 {
		return nil, errors.New("invalid entries")
	}
	for i, raw := range entries {
		var item map[string]json.RawMessage
		if json.Unmarshal(raw, &item) != nil || item == nil {
			return nil, errors.New("invalid entry")
		}
		var name string
		if rawName, ok := item["name"]; !ok || len(rawName) == 0 || rawName[0] != '"' || json.Unmarshal(rawName, &name) != nil {
			return nil, errors.New("invalid entry name")
		}
		item["display_name"], _ = json.Marshal(displayName(name))
		entries[i], err = json.Marshal(item)
		if err != nil {
			return nil, err
		}
	}
	response[key], err = json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	return json.Marshal(response)
}

func agentListingKey(resource, method string) string {
	if method != http.MethodGet {
		return ""
	}
	parts := strings.Split(strings.Trim(resource, "/"), "/")
	if len(parts) < 3 || parts[0] != "mounts" || parts[2] != "files" {
		return ""
	}
	if len(parts) == 3 {
		return "items"
	}
	if len(parts) == 4 && parts[3] == "search" {
		return "entries"
	}
	return ""
}

func decorateAgentListingResponse(w http.ResponseWriter, r *http.Request, response *http.Response, key string, agent agentContext) bool {
	if key == "" || response.StatusCode != http.StatusOK {
		return true
	}
	limit := agent.limits.MaxResponseBytes
	if agent.budget < limit {
		limit = agent.budget
	}
	data, err := decorateAgentEntries(response.Body, key, limit)
	if err != nil {
		if errors.Is(err, errListingTooLarge) {
			if agent.budget < agent.limits.MaxResponseBytes {
				w.Header().Set("Retry-After", secondsUntilNextUTCDay(time.Now()))
				writeError(w, r, http.StatusTooManyRequests, "agent_daily_quota", "A resposta excede a cota diária restante.")
			} else {
				writeError(w, r, http.StatusRequestEntityTooLarge, "read_too_large", "A resposta excede o limite de leitura do agente.")
			}
			return false
		}
		writeError(w, r, http.StatusBadGateway, "invalid_node_listing", "Não foi possível validar a listagem retornada pelo node.")
		return false
	}
	if int64(len(data)) > agent.limits.MaxResponseBytes {
		writeError(w, r, http.StatusRequestEntityTooLarge, "read_too_large", "A resposta excede o limite de leitura do agente.")
		return false
	}
	if int64(len(data)) > agent.budget {
		w.Header().Set("Retry-After", secondsUntilNextUTCDay(time.Now()))
		writeError(w, r, http.StatusTooManyRequests, "agent_daily_quota", "A resposta excede a cota diária restante.")
		return false
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	response.ContentLength = int64(len(data))
	response.Header.Set("Content-Length", fmt.Sprint(len(data)))
	response.Header.Del("Content-Encoding")
	return true
}
