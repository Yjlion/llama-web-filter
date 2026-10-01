package logstore

import (
	"database/sql"
	"fmt"
)

// validKinds restricts Tail/RowsInRange's kind parameter to the two real
// tables, matching the Python original's whitelist (query built by string
// formatting the table name, so this check is what keeps that safe).
func validKind(kind string) error {
	if kind != "requests" && kind != "blocks" && kind != "policy_changes" {
		return fmt.Errorf("invalid kind %q: must be \"requests\", \"blocks\", or \"policy_changes\"", kind)
	}
	return nil
}

// Tail returns up to limit most-recent rows from kind ("requests" or
// "blocks"), newest first, as column-name-keyed maps (mirrors the Python
// original's dict-per-row shape used directly as JSON API responses). The
// internal "id" column is omitted. Returns an empty slice (never an error)
// on any query failure, matching the Python original's fail-open read path.
func (r *Reader) Tail(kind string, limit int) []map[string]any {
	if err := validKind(kind); err != nil {
		return []map[string]any{}
	}
	db, err := r.openReadConn()
	if err != nil {
		return []map[string]any{}
	}
	defer db.Close()

	query := fmt.Sprintf("SELECT * FROM %s ORDER BY ts DESC, id DESC LIMIT ?", kind)
	rows, err := db.Query(query, limit)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	return rowsToMaps(rows)
}

// RowsInRange returns every row of kind with startTs <= ts <= endTs,
// ascending by ts - used for CSV/XLSX export.
func (r *Reader) RowsInRange(kind string, startTs, endTs int64) []map[string]any {
	if err := validKind(kind); err != nil {
		return []map[string]any{}
	}
	db, err := r.openReadConn()
	if err != nil {
		return []map[string]any{}
	}
	defer db.Close()

	query := fmt.Sprintf("SELECT * FROM %s WHERE ts >= ? AND ts <= ? ORDER BY ts ASC", kind)
	rows, err := db.Query(query, startTs, endTs)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	return rowsToMaps(rows)
}

func rowsToMaps(rows *sql.Rows) []map[string]any {
	cols, err := rows.Columns()
	if err != nil {
		return []map[string]any{}
	}
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		m := make(map[string]any, len(cols)-1)
		for i, c := range cols {
			if c == "id" {
				continue
			}
			m[c] = vals[i]
		}
		out = append(out, m)
	}
	return out
}

// Analytics aggregates activity since startTs (Unix seconds) for the
// dashboard/analytics page, mirroring shared/logstore.py's analytics()
// query-for-query.
type Analytics struct {
	WindowHours       int              `json:"window_hours"`
	TotalRequests     int              `json:"total_requests"`
	TotalBlocks       int              `json:"total_blocks"`
	RequestActions    map[string]int   `json:"request_actions"`
	TopBlockedDomains []DomainCount    `json:"top_blocked_domains"`
	BlocksByComponent []ComponentCount `json:"blocks_by_component"`
	PerDevice         []DeviceStats    `json:"per_device"`
	BlocksTimeline    []TimelineBucket `json:"blocks_timeline"`
}

type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

type ComponentCount struct {
	Component string `json:"component"`
	Count     int    `json:"count"`
}

type DeviceStats struct {
	ClientIP string `json:"client_ip"`
	Total    int    `json:"total"`
	Blocked  int    `json:"blocked"`
	Policy   string `json:"policy"`
}

type TimelineBucket struct {
	TS    int64 `json:"ts"`
	Count int   `json:"count"`
}

func emptyAnalytics(windowHours int) Analytics {
	return Analytics{
		WindowHours:       windowHours,
		RequestActions:    map[string]int{},
		TopBlockedDomains: []DomainCount{},
		BlocksByComponent: []ComponentCount{},
		PerDevice:         []DeviceStats{},
		BlocksTimeline:    []TimelineBucket{},
	}
}

func (r *Reader) Analytics(startTs int64, windowHours int) Analytics {
	result := emptyAnalytics(windowHours)

	db, err := r.openReadConn()
	if err != nil {
		return result
	}
	defer db.Close()

	if err := db.QueryRow("SELECT COUNT(*) FROM requests WHERE ts >= ?", startTs).Scan(&result.TotalRequests); err != nil {
		return emptyAnalytics(windowHours)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM blocks WHERE ts >= ?", startTs).Scan(&result.TotalBlocks); err != nil {
		return emptyAnalytics(windowHours)
	}

	if rows, err := db.Query("SELECT action, COUNT(*) FROM requests WHERE ts >= ? GROUP BY action", startTs); err == nil {
		defer rows.Close()
		for rows.Next() {
			var action sql.NullString
			var count int
			if rows.Scan(&action, &count) == nil {
				key := action.String
				if key == "" {
					key = "ok"
				}
				result.RequestActions[key] = count
			}
		}
	}

	if rows, err := db.Query(`SELECT domain, COUNT(*) c FROM blocks
		WHERE ts >= ? AND domain <> '' AND domain IS NOT NULL
		GROUP BY domain ORDER BY c DESC LIMIT 15`, startTs); err == nil {
		defer rows.Close()
		for rows.Next() {
			var dc DomainCount
			if rows.Scan(&dc.Domain, &dc.Count) == nil {
				result.TopBlockedDomains = append(result.TopBlockedDomains, dc)
			}
		}
	}

	if rows, err := db.Query(`SELECT COALESCE(component, 'unknown'), COUNT(*) c FROM blocks
		WHERE ts >= ? GROUP BY component ORDER BY c DESC`, startTs); err == nil {
		defer rows.Close()
		for rows.Next() {
			var cc ComponentCount
			if rows.Scan(&cc.Component, &cc.Count) == nil {
				result.BlocksByComponent = append(result.BlocksByComponent, cc)
			}
		}
	}

	if rows, err := db.Query(`SELECT COALESCE(client_ip, 'unknown'), COUNT(*) total,
		SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) blocked, MAX(policy)
		FROM requests WHERE ts >= ? GROUP BY client_ip ORDER BY total DESC`, startTs); err == nil {
		defer rows.Close()
		for rows.Next() {
			var d DeviceStats
			var policy sql.NullString
			if rows.Scan(&d.ClientIP, &d.Total, &d.Blocked, &policy) == nil {
				d.Policy = policy.String
				result.PerDevice = append(result.PerDevice, d)
			}
		}
	}

	if rows, err := db.Query(`SELECT (ts/3600)*3600 bucket, COUNT(*) c FROM blocks
		WHERE ts >= ? GROUP BY bucket ORDER BY bucket`, startTs); err == nil {
		defer rows.Close()
		for rows.Next() {
			var b TimelineBucket
			if rows.Scan(&b.TS, &b.Count) == nil {
				result.BlocksTimeline = append(result.BlocksTimeline, b)
			}
		}
	}

	return result
}
