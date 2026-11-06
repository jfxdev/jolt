package httpapi

import (
	"errors"
	"strings"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
)

// buildMountAccessContext constructs the complete effective file-rule context
// for one concrete mount. It is not sent to nodes until every operation can
// enforce it. Oversized or invalid policy sets are rejected, never truncated.
func buildMountAccessContext(policies []rbac.Policy, mountScope string) (filetypes.Context, error) {
	mountScope = rbac.NormalizePath(mountScope)
	parts := strings.Split(mountScope, "/")
	if len(parts) != 5 || parts[0] != "nodes" || parts[2] != "files" || parts[3] != "mounts" || !rbac.ValidResourcePath(mountScope) {
		return filetypes.Context{}, errors.New("invalid mount authorization scope")
	}
	context := filetypes.Context{Version: 1, Rules: []filetypes.Rule{}}
	for _, policy := range rbac.ExpandCompatibilityRules(policies) {
		for _, rule := range policy.Rules {
			if !rbac.ValidPath(rule.Path) {
				return filetypes.Context{}, errors.New("invalid policy rule path")
			}
			if !rbac.RuleTouchesScope(rule.Path, mountScope) {
				continue
			}
			if len(context.Rules) == filetypes.MaxContextRules {
				return filetypes.Context{}, errors.New("authorization context has too many rules")
			}
			var selector *filetypes.Selector
			if rule.FileTypes != nil {
				selector = &filetypes.Selector{
					Classes:    append([]string(nil), rule.FileTypes.Classes...),
					Extensions: append([]string(nil), rule.FileTypes.Extensions...),
					Names:      append([]string(nil), rule.FileTypes.Names...),
				}
			}
			context.Rules = append(context.Rules, filetypes.Rule{
				PolicyID: policy.ID, Path: rbac.NormalizePath(rule.Path), Capabilities: append([]string(nil), rule.Capabilities...),
				FileTypes: selector, Visibility: rule.Visibility,
			})
		}
	}
	if _, err := context.Compile(); err != nil {
		return filetypes.Context{}, err
	}
	return context, nil
}
