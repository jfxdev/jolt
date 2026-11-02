package httpapi

import "testing"

func TestTransferGrantExclusionsAreReflectedInSelection(t *testing.T) {
	grant := nodeTransferGrant{Enabled: true, PeerNodeID: "peer", MountID: "media", Path: ".", Direction: "send", Exclude: []string{"*.pem", "private"}}
	grant.Permissions.Read = true
	if !sourceGrantAllows(grant, "peer", "media", []string{"public/report.txt"}, "copy") {
		t.Fatal("allowed source was rejected")
	}
	for _, name := range []string{"public/key.PEM", "private/file.txt"} {
		if sourceGrantAllows(grant, "peer", "media", []string{name}, "copy") {
			t.Fatalf("excluded source %q was accepted", name)
		}
	}
	grant.Exclude = []string{"[invalid"}
	if sourceGrantAllows(grant, "peer", "media", []string{"public"}, "copy") {
		t.Fatal("invalid exclusion was ignored")
	}
	grant.Direction = "receive"
	grant.Permissions.Write = true
	if destinationGrantAllows(grant, "peer") {
		t.Fatal("invalid receiving exclusion was advertised")
	}
	grant.Exclude = []string{"*.pem"}
	if !destinationGrantAllows(grant, "peer") || grantAllowsPath(grant, "folder/key.PEM") || !grantAllowsPath(grant, "folder/report.txt") {
		t.Fatal("receiving exclusions were not applied to destination paths")
	}
	if got := grantsSupportedByNode([]nodeTransferGrant{grant}, nil, "grant_exclude_receive_v1"); len(got) != 0 {
		t.Fatal("an incompatible node was allowed to enforce receiving exclusions")
	}
	if got := grantsSupportedByNode([]nodeTransferGrant{grant}, []string{"grant_exclude_receive_v1"}, "grant_exclude_receive_v1"); len(got) != 1 {
		t.Fatal("a compatible node was rejected")
	}
}
