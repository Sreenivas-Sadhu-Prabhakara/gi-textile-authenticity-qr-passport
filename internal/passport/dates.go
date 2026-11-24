package passport

import (
	"fmt"
	"time"
)

// DateLayout is the only date format a passport uses. One format, written the
// same way everywhere, because a date that could be read two ways is a date a
// forger can argue about.
const DateLayout = "2006-01-02"

// EarliestOffLoomDate is a sanity floor, not a rule: a piece recorded as
// coming off the loom before this is almost certainly a typing mistake in the
// year. It is a named constant so a cluster documenting genuinely older cloth
// can see exactly what to change.
const EarliestOffLoomDate = "1950-01-01"

// ParseDate reads a date strictly: four digits, two digits, two digits,
// separated by hyphens, and a day that exists in that month of that year. A
// date written the Indian way, a month without its leading zero, and the 30th
// of February are all refused rather than quietly becoming something else.
// 29 February is accepted in a leap year and refused in any other.
func ParseDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("the date is empty")
	}
	t, err := time.Parse(DateLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a date written as YYYY-MM-DD", s)
	}
	return t, nil
}

// Today returns the date part of a moment, in its own location. The rules work
// on whole days, so trimming the clock time keeps a passport issued at one
// minute past midnight from behaving differently from one issued at noon.
func Today(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}

// DaysBetween counts whole days from one date to another. It works on the
// calendar rather than on elapsed hours, so it is right across a leap day and
// across a daylight-saving change.
func DaysBetween(from, to time.Time) int {
	a := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC)
	b := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, time.UTC)
	return int(b.Sub(a).Hours() / 24)
}

// AgeInWords describes how long ago a piece came off the loom, for a buyer
// standing in a shop. Handwoven cloth is often months old by the time it is
// sold, so the point is not freshness: it is that a date in the future, or a
// date that does not match a shopworn piece, is worth a question.
func AgeInWords(offLoom, now time.Time) string {
	days := DaysBetween(offLoom, Today(now))
	switch {
	case days < 0:
		return fmt.Sprintf("dated %d days in the future", -days)
	case days == 0:
		return "came off the loom today"
	case days == 1:
		return "came off the loom yesterday"
	case days < 31:
		return fmt.Sprintf("came off the loom %d days ago", days)
	case days < 365:
		months := days / 30
		if months == 1 {
			return "came off the loom about a month ago"
		}
		return fmt.Sprintf("came off the loom about %d months ago", months)
	default:
		years := days / 365
		if years == 1 {
			return "came off the loom about a year ago"
		}
		return fmt.Sprintf("came off the loom about %d years ago", years)
	}
}
