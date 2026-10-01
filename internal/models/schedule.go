package models

import (
	"strconv"
	"strings"
	"time"
)

// TimeWindow is a recurring weekly time window. Days use ISO weekday - 1
// (0=Monday ... 6=Sunday), matching the Python original exactly (Python's
// datetime.weekday() also returns 0=Monday).
type TimeWindow struct {
	Days  []int  `json:"days"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// DefaultTimeWindow mirrors the Python model's field defaults: all 7 days,
// the full 00:00-23:59 range.
func DefaultTimeWindow() TimeWindow {
	return TimeWindow{
		Days:  []int{0, 1, 2, 3, 4, 5, 6},
		Start: "00:00",
		End:   "23:59",
	}
}

// normalizeDays mirrors the Pydantic validator: mod-7 wrap, non-int values
// dropped (not applicable in Go's typed []int, but out-of-range ints still
// get wrapped the same way).
func normalizeDays(days []int) []int {
	out := make([]int, 0, len(days))
	for _, d := range days {
		out = append(out, ((d%7)+7)%7)
	}
	return out
}

// parseHHMM validates and normalizes an "HH:MM" string, zero-padded,
// mirroring the Pydantic field_validator on TimeWindow.start/end.
func parseHHMM(v string) (string, bool) {
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return "", false
	}
	return strconv.Itoa(h/10) + strconv.Itoa(h%10) + ":" + strconv.Itoa(m/10) + strconv.Itoa(m%10), true
}

// Normalize applies the same validation/normalization the Pydantic model
// performs on unmarshal: day wrap + zero-padded HH:MM, falling back to
// defaults for unparseable time strings (fail open, never reject the whole
// policy over a malformed schedule field).
func (w *TimeWindow) Normalize() {
	if w.Days == nil {
		w.Days = DefaultTimeWindow().Days
	} else {
		w.Days = normalizeDays(w.Days)
	}
	if v, ok := parseHHMM(w.Start); ok {
		w.Start = v
	} else if w.Start == "" {
		w.Start = "00:00"
	}
	if v, ok := parseHHMM(w.End); ok {
		w.End = v
	} else if w.End == "" {
		w.End = "23:59"
	}
}

// ScheduleConfig controls when a policy is active.
type ScheduleConfig struct {
	Enabled       bool         `json:"enabled"`
	ActiveWindows []TimeWindow `json:"active_windows"`
}

// IsActiveNow returns true if the current local time falls inside any
// active window. Disabled schedules, or schedules with no windows
// configured, are always active (fail-open) - this lets PolicyRouter treat
// "no schedule" identically to "always match" for every existing policy
// file that predates the scheduling feature.
func (s ScheduleConfig) IsActiveNow() bool {
	return s.IsActiveAt(time.Now())
}

// IsActiveAt is the testable form of IsActiveNow. Windows whose end time is
// earlier than their start time are treated as overnight windows: a Monday
// 22:00-06:00 window is active late Monday and early Tuesday.
func (s ScheduleConfig) IsActiveAt(now time.Time) bool {
	if !s.Enabled || len(s.ActiveWindows) == 0 {
		return true
	}
	weekday := (int(now.Weekday()) + 6) % 7 // Go: Sunday=0..Saturday=6 -> Monday=0..Sunday=6
	hm := now.Hour()*60 + now.Minute()

	for _, w := range s.ActiveWindows {
		days := w.Days
		if days == nil {
			days = DefaultTimeWindow().Days
		}
		start, ok1 := parseHHMM(orDefault(w.Start, "00:00"))
		end, ok2 := parseHHMM(orDefault(w.End, "23:59"))
		if !ok1 {
			start = "00:00"
		}
		if !ok2 {
			end = "23:59"
		}
		sh, sm := splitHHMM(start)
		eh, em := splitHHMM(end)
		startMin := sh*60 + sm
		endMin := eh*60 + em
		if startMin <= endMin {
			if containsDay(days, weekday) && hm >= startMin && hm <= endMin {
				return true
			}
			continue
		}
		if containsDay(days, weekday) && hm >= startMin {
			return true
		}
		prevWeekday := (weekday + 6) % 7
		if containsDay(days, prevWeekday) && hm <= endMin {
			return true
		}
	}
	return false
}

func containsDay(days []int, weekday int) bool {
	for _, d := range normalizeDays(days) {
		if d == weekday {
			return true
		}
	}
	return false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func splitHHMM(v string) (int, int) {
	parts := strings.SplitN(v, ":", 2)
	h, _ := strconv.Atoi(parts[0])
	m, _ := strconv.Atoi(parts[1])
	return h, m
}
