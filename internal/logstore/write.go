package logstore

import "fmt"

// RequestEntry is one row of the requests table - the audit-log record for
// every proxied HTTP(S) request, written by the RequestLogger addon.
type RequestEntry struct {
	TS        int64
	Method    string
	Host      string
	Path      string
	Status    int
	Action    string // "ok" | "blocked" | "modified"
	Component string
	Policy    string
	ClientIP  string
	UserAgent string
}

// BlockEntry is one row of the blocks table, written whenever any
// filtering addon blocks a request (block.LogBlock).
type BlockEntry struct {
	TS        int64
	Domain    string
	URL       string
	Reason    string
	Component string
	Policy    string
	ClientIP  string
}

// PolicyChangeEntry is one row of the policy_changes table, written by the
// management API whenever a policy is created, updated, or deleted. OldName
// is only set on an update that renames the policy.
type PolicyChangeEntry struct {
	TS         int64
	Action     string // "created" | "updated" | "deleted"
	PolicyName string
	OldName    string
	ClientIP   string
}

// LogRequest inserts a request row. No-op if log_requests is disabled or
// the store wasn't configured for it.
func (s *Store) LogRequest(e RequestEntry) error {
	if !s.logRequests {
		return nil
	}
	return s.insert("requests", RequestColumns, []any{
		e.TS, e.Method, e.Host, e.Path, e.Status, e.Action, e.Component, e.Policy, e.ClientIP, e.UserAgent,
	})
}

// LogBlock inserts a block row. No-op if log_blocks is disabled.
func (s *Store) LogBlock(e BlockEntry) error {
	if !s.logBlocks {
		return nil
	}
	return s.insert("blocks", BlockColumns, []any{
		e.TS, e.Domain, e.URL, e.Reason, e.Component, e.Policy, e.ClientIP,
	})
}

// LogPolicyChange inserts a policy_changes row. Unlike LogRequest/LogBlock,
// this is never gated by a settings toggle - policy-change auditing is
// always on.
func (s *Store) LogPolicyChange(e PolicyChangeEntry) error {
	return s.insert("policy_changes", PolicyChangeColumns, []any{
		e.TS, e.Action, e.PolicyName, e.OldName, e.ClientIP,
	})
}

func (s *Store) insert(table string, columns []string, values []any) error {
	placeholders := make([]string, len(columns))
	for i := range columns {
		placeholders[i] = "?"
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, joinCols(columns), joinCols(placeholders))

	s.writeMu.Lock()
	_, err := s.writeDB.Exec(query, values...)
	s.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("insert into %s: %w", table, err)
	}

	if s.insertCount.Add(1)%pruneEvery == 0 {
		s.Prune()
	}
	return nil
}

func joinCols(cols []string) string {
	out := cols[0]
	for _, c := range cols[1:] {
		out += ", " + c
	}
	return out
}
