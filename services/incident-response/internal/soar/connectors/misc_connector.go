package connectors

import (
	"context"
	"fmt"
	"log"
	"time"
)

// MiscConnector handles actions that don't need external API calls
// (scripts, forensic snapshots, credential ops, etc.).
// These are local/internal operations that produce evidence output.
type MiscConnector struct {
	simulate bool
}

// NewMiscConnector creates a miscellaneous actions connector.
func NewMiscConnector(simulate bool) *MiscConnector {
	return &MiscConnector{simulate: simulate}
}

func (c *MiscConnector) Name() string { return "misc" }

func (c *MiscConnector) SupportsRollback(_ string) bool { return false }

func (c *MiscConnector) Rollback(_ context.Context, action string, _ map[string]any) error {
	return fmt.Errorf("misc: rollback not supported for %s", action)
}

func (c *MiscConnector) Execute(_ context.Context, action string, params map[string]any) (*ActionOutput, error) {
	start := time.Now()
	time.Sleep(100 * time.Millisecond) // simulate processing time

	log.Printf("[Misc] Executing action: %s (params: %v)", action, params)

	fields := make(map[string]any)
	var evidenceURL string

	switch action {
	case "run_script":
		script, _ := params["script"].(string)
		fields["script"] = script
		fields["exit_code"] = 0
		fields["stdout"] = "Script executed successfully"
		evidenceURL = fmt.Sprintf("https://soar.internal/scripts/run-%d", time.Now().UnixMilli())

	case "snapshot_forensic":
		host, _ := params["host"].(string)
		snapID := fmt.Sprintf("snap-%s-%d", host, time.Now().Unix())
		fields["snapshot_id"] = snapID
		fields["host"] = host
		fields["includes"] = []string{"memory_dump", "disk_image", "process_list", "network_state"}
		evidenceURL = fmt.Sprintf("https://forensics.internal/snapshots/%s", snapID)

	case "restore_backup":
		host, _ := params["host"].(string)
		fields["host"] = host
		fields["restored"] = true
		fields["backup_id"] = fmt.Sprintf("bk-%s-latest", host)
		evidenceURL = fmt.Sprintf("https://backup.internal/restores/%d", time.Now().UnixMilli())

	case "revoke_creds":
		user, _ := params["user"].(string)
		fields["user"] = user
		fields["revoked"] = true
		fields["sessions_terminated"] = 3
		evidenceURL = fmt.Sprintf("https://iam.internal/users/%s/revocations", user)

	case "vulnerability_scan":
		host, _ := params["host"].(string)
		fields["host"] = host
		fields["vulnerabilities_found"] = 2
		fields["scan_id"] = fmt.Sprintf("scan-%d", time.Now().UnixMilli())
		evidenceURL = fmt.Sprintf("https://vuln-scanner.internal/scans/%d", time.Now().UnixMilli())

	case "patch":
		fields["patch_applied"] = true
		fields["patch_id"] = fmt.Sprintf("patch-%d", time.Now().UnixMilli())

	case "quarantine_email":
		fields["quarantined"] = true
		fields["mailboxes_cleaned"] = 47
		evidenceURL = fmt.Sprintf("https://mail.internal/quarantine/%d", time.Now().UnixMilli())

	case "block_domain":
		domain, _ := params["domain"].(string)
		fields["domain"] = domain
		fields["blocked"] = true

	case "endpoint_scan":
		fields["scanned"] = true
		fields["threats_found"] = 0

	case "reset_password":
		fields["reset"] = true
		fields["users_affected"] = 5

	case "collect_logs":
		fields["collected"] = true
		fields["log_bundle"] = fmt.Sprintf("logs-%d.tar.gz", time.Now().UnixMilli())
		evidenceURL = fmt.Sprintf("https://logs.internal/bundles/%d", time.Now().UnixMilli())

	default:
		fields["action"] = action
		fields["status"] = "completed"
	}

	return &ActionOutput{
		Fields:      fields,
		EvidenceURL: evidenceURL,
		Connector:   "misc",
		Simulated:   c.simulate,
		Timestamp:   time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}
