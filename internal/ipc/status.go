package ipc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	// maxStatusItems bounds each list of a status report.
	maxStatusItems = 1024
	// maxStatusText bounds each string of a status report, in bytes.
	maxStatusText = 1024
	// cutMarker ends a string that the server cut to its bound.
	cutMarker = " [cut]"
	// envelopeRoom is the frame space that the envelope around a body
	// takes, with a wide margin.
	envelopeRoom = 256
)

// State is the lifecycle state of ifboundd. On the wire, it is the
// lower-case name.
type State uint8

// The lifecycle states. The zero State is StateStarting.
const (
	// StateStarting: the daemon has not loaded its snapshot.
	StateStarting State = iota
	// StateReady: enforcement is installed, and nothing reports a
	// problem.
	StateReady
	// StateDegraded: enforcement is installed, but a problem exists that
	// does not void it.
	StateDegraded
	// StateUnenforced: enforcement is not installed, or a problem voids
	// it.
	StateUnenforced
)

// String returns the lower-case state name.
func (s State) String() string {
	switch s {
	case StateStarting:
		return "starting"
	case StateReady:
		return "ready"
	case StateDegraded:
		return "degraded"
	case StateUnenforced:
		return "unenforced"
	default:
		return "unknown"
	}
}

// parseState reads a state name from the wire. An unknown name is a
// protocol error.
func parseState(name string) (State, error) {
	switch name {
	case "starting":
		return StateStarting, nil
	case "ready":
		return StateReady, nil
	case "degraded":
		return StateDegraded, nil
	case "unenforced":
		return StateUnenforced, nil
	default:
		return 0, fmt.Errorf("%w: unknown state %.64q", ErrProtocol, name)
	}
}

// StatusReport is the status of ifboundd for the CLI. The server bounds
// it before it sends it: each list has at most 1024 items, and each
// string at most 1024 bytes. A longer string ends in " [cut]". A longer
// list ends in one item that counts the items left out.
type StatusReport struct {
	// Daemon is the build version of ifboundd.
	Daemon string
	State  State
	// Reasons explains every state but StateReady.
	Reasons  []string
	Warnings []Warning
	// Policies counts the learned addresses of each policy. The sum is
	// the number of learned addresses.
	Policies []PolicyCount
	// RetainRestart is true when only a restart applies the configured
	// retain.
	RetainRestart bool
	// Config is the sha256 of the applied configuration, in hex.
	Config string
}

// Warning is a problem that does not change the state.
type Warning struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

// PolicyCount is the number of learned addresses of one policy.
type PolicyCount struct {
	Name  string `json:"name"`
	Addrs int    `json:"addrs"`
}

type statusBody struct {
	Daemon        string        `json:"daemon"`
	State         string        `json:"state"`
	Reasons       []string      `json:"reasons"`
	Warnings      []Warning     `json:"warnings"`
	Policies      []PolicyCount `json:"policies"`
	RetainRestart bool          `json:"retain_restart"`
	Config        string        `json:"config"`
}

// boundStatus returns the body of r in the bounds that decodeStatus
// checks, and small enough for one frame. When the body is too large, it
// keeps fewer items in each list.
func boundStatus(r StatusReport) statusBody {
	for items := maxStatusItems; ; items /= 2 {
		b := encodeStatus(r, items)
		// One item in each list and 1024 bytes in each string always fit.
		if items == 1 || fitsFrame(b) {
			return b
		}
	}
}

func fitsFrame(b statusBody) bool {
	raw, err := json.Marshal(b)
	if err != nil {
		panic("ipc: status body does not marshal: " + err.Error())
	}
	return len(raw) <= MaxFrameSize-envelopeRoom
}

// encodeStatus keeps at most items items in each list and cuts each
// string to maxStatusText.
func encodeStatus(r StatusReport, items int) statusBody {
	reasons := capList(r.Reasons, items, func(left []string) string {
		return fmt.Sprintf("[%d more reasons]", len(left))
	})
	warnings := capList(r.Warnings, items, func(left []Warning) Warning {
		return Warning{Source: "ipc", Text: fmt.Sprintf("[%d more warnings]", len(left))}
	})
	policies := capList(r.Policies, items, func(left []PolicyCount) PolicyCount {
		n := 0
		for _, p := range left {
			n += p.Addrs
		}
		return PolicyCount{Name: fmt.Sprintf("[%d more policies]", len(left)), Addrs: n}
	})
	for i, s := range reasons {
		reasons[i] = cutText(s, maxStatusText)
	}
	for i, w := range warnings {
		warnings[i] = Warning{Source: cutText(w.Source, maxStatusText), Text: cutText(w.Text, maxStatusText)}
	}
	for i, p := range policies {
		policies[i].Name = cutText(p.Name, maxStatusText)
	}
	return statusBody{
		Daemon:        cutText(r.Daemon, maxStatusText),
		State:         r.State.String(),
		Reasons:       reasons,
		Warnings:      warnings,
		Policies:      policies,
		RetainRestart: r.RetainRestart,
		Config:        r.Config,
	}
}

// capList returns a copy of list with at most limit items. When list is
// longer, the last item of the copy is more of the items left out.
func capList[T any](list []T, limit int, more func(left []T) T) []T {
	if len(list) <= limit {
		return slices.Clone(list)
	}
	return append(slices.Clone(list[:limit-1]), more(list[limit-1:]))
}

// cutText returns s as valid UTF-8 of at most limit bytes. It replaces
// invalid bytes with U+FFFD, as JSON would. A longer s ends in cutMarker.
func cutText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= limit {
		return s
	}
	n := limit - len(cutMarker)
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + cutMarker
}

// decodeStatus reads the status in the body of an ack. A body out of
// bounds is a protocol error.
func decodeStatus(raw json.RawMessage) (StatusReport, error) {
	var b statusBody
	if err := json.Unmarshal(raw, &b); err != nil {
		return StatusReport{}, fmt.Errorf("%w: status body: %v", ErrProtocol, err)
	}
	state, err := parseState(b.State)
	if err != nil {
		return StatusReport{}, err
	}
	if err := checkStatus(b); err != nil {
		return StatusReport{}, err
	}
	return StatusReport{
		Daemon:        b.Daemon,
		State:         state,
		Reasons:       b.Reasons,
		Warnings:      b.Warnings,
		Policies:      b.Policies,
		RetainRestart: b.RetainRestart,
		Config:        b.Config,
	}, nil
}

// checkStatus bounds every list, string, and count of b. It returns an
// ErrProtocol for a value out of bounds.
func checkStatus(b statusBody) error {
	if n := max(len(b.Reasons), len(b.Warnings), len(b.Policies)); n > maxStatusItems {
		return fmt.Errorf("%w: status list of %d items", ErrProtocol, n)
	}
	texts := append([]string{b.Daemon}, b.Reasons...)
	for _, w := range b.Warnings {
		texts = append(texts, w.Source, w.Text)
	}
	for _, p := range b.Policies {
		if p.Addrs < 0 {
			return fmt.Errorf("%w: status policy addrs %d", ErrProtocol, p.Addrs)
		}
		texts = append(texts, p.Name)
	}
	for _, s := range texts {
		if len(s) > maxStatusText {
			return fmt.Errorf("%w: status text of %d bytes", ErrProtocol, len(s))
		}
	}
	if b.Config != "" {
		if sum, err := hex.DecodeString(b.Config); err != nil || len(sum) != sha256.Size {
			return fmt.Errorf("%w: config %.80q is not a sha256 in hex", ErrProtocol, b.Config)
		}
	}
	return nil
}
