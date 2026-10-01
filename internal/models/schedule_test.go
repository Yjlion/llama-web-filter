package models_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/models"
)

func TestScheduleIsActiveNowFailOpen(t *testing.T) {
	// Disabled schedule, or enabled with no windows: always active.
	s := models.ScheduleConfig{}
	if !s.IsActiveNow() {
		t.Errorf("disabled schedule should be active (fail-open)")
	}
	s2 := models.ScheduleConfig{Enabled: true}
	if !s2.IsActiveNow() {
		t.Errorf("enabled schedule with no windows should be active (fail-open)")
	}
}

func hhmm(t time.Time) string {
	return fmt.Sprintf("%02d:%02d", t.Hour(), t.Minute())
}

func TestScheduleIsActiveNowMatchesCurrentWindow(t *testing.T) {
	now := time.Now()
	weekday := (int(now.Weekday()) + 6) % 7 // Monday=0..Sunday=6

	s := models.ScheduleConfig{
		Enabled: true,
		ActiveWindows: []models.TimeWindow{
			{
				Days:  []int{weekday},
				Start: hhmm(now.Add(-time.Minute)),
				End:   hhmm(now.Add(time.Minute)),
			},
		},
	}
	if !s.IsActiveNow() {
		t.Errorf("expected active: current time falls inside the configured window")
	}
}

func TestScheduleIsActiveNowWrongDay(t *testing.T) {
	now := time.Now()
	weekday := (int(now.Weekday()) + 6) % 7
	wrongDay := (weekday + 1) % 7

	s := models.ScheduleConfig{
		Enabled: true,
		ActiveWindows: []models.TimeWindow{
			{Days: []int{wrongDay}, Start: "00:00", End: "23:59"},
		},
	}
	if s.IsActiveNow() {
		t.Errorf("expected inactive: window is for a different weekday")
	}
}

func TestScheduleIsActiveNowOutsideTimeRange(t *testing.T) {
	now := time.Now()
	weekday := (int(now.Weekday()) + 6) % 7

	s := models.ScheduleConfig{
		Enabled: true,
		ActiveWindows: []models.TimeWindow{
			{
				Days:  []int{weekday},
				Start: hhmm(now.Add(5 * time.Minute)),
				End:   hhmm(now.Add(10 * time.Minute)),
			},
		},
	}
	if s.IsActiveNow() {
		t.Errorf("expected inactive: current time is before the configured window")
	}
}

func TestScheduleIsActiveAtOvernightSameDay(t *testing.T) {
	s := models.ScheduleConfig{
		Enabled: true,
		ActiveWindows: []models.TimeWindow{
			{Days: []int{0}, Start: "22:00", End: "06:00"},
		},
	}
	now := time.Date(2026, 6, 29, 23, 30, 0, 0, time.Local) // Monday
	if !s.IsActiveAt(now) {
		t.Errorf("expected active late on the configured start day")
	}
}

func TestScheduleIsActiveAtOvernightNextMorning(t *testing.T) {
	s := models.ScheduleConfig{
		Enabled: true,
		ActiveWindows: []models.TimeWindow{
			{Days: []int{0}, Start: "22:00", End: "06:00"},
		},
	}
	now := time.Date(2026, 6, 30, 5, 30, 0, 0, time.Local) // Tuesday
	if !s.IsActiveAt(now) {
		t.Errorf("expected active early on the morning after the configured start day")
	}
}

func TestScheduleIsActiveAtOvernightWrongMorning(t *testing.T) {
	s := models.ScheduleConfig{
		Enabled: true,
		ActiveWindows: []models.TimeWindow{
			{Days: []int{0}, Start: "22:00", End: "06:00"},
		},
	}
	now := time.Date(2026, 7, 1, 5, 30, 0, 0, time.Local) // Wednesday
	if s.IsActiveAt(now) {
		t.Errorf("expected inactive on a morning not covered by the previous configured day")
	}
}

func TestTimeWindowNormalizeDayWrap(t *testing.T) {
	w := models.TimeWindow{Days: []int{-1, 7, 8}}
	w.Normalize()
	want := []int{6, 0, 1}
	if len(w.Days) != len(want) {
		t.Fatalf("Days = %v, want %v", w.Days, want)
	}
	for i, d := range want {
		if w.Days[i] != d {
			t.Errorf("Days[%d] = %d, want %d", i, w.Days[i], d)
		}
	}
}
