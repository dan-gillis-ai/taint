// Package taint implements the trust-label lattice that is the core security
// control of the harness. It is deliberately duplicated in Go and Python from a
// single source of truth (proto/taint.proto) and verified against shared test
// vectors, because the enforcement point is the Go device agent while labelling
// happens in Python. If these two disagree, the device must be right.
//
// The lattice is a total order: Trusted < Semi < Untrusted < Hostile.
//
//	Lattice levels, in ascending order of distrust:
//
//	 0  TRUSTED   curated internal docs, operator-authored config
//	 1  SEMI      model output, git diffs, user-typed input, existing local files
//	 2  UNTRUSTED web fetches, third-party MCP servers, unknown-origin repo files
//	 3  HOSTILE   blocklisted sources, content flagged by the redaction filter
//
// Propagation is join (max). Model output is never Trusted: the model is a
// confused-deputy risk by construction and must not launder trust.
package taint

import "fmt"

// Level is a position in the trust lattice.
type Level uint8

const (
	Trusted   Level = 0
	Semi      Level = 1
	Untrusted Level = 2
	Hostile   Level = 3
)

// AllLevels is the full lattice, ascending.
var AllLevels = []Level{Trusted, Semi, Untrusted, Hostile}

func (l Level) String() string {
	switch l {
	case Trusted:
		return "trusted"
	case Semi:
		return "semi"
	case Untrusted:
		return "untrusted"
	case Hostile:
		return "hostile"
	default:
		return fmt.Sprintf("invalid(%d)", uint8(l))
	}
}

// MarshalText implements encoding.TextMarshaler.
func (l Level) MarshalText() ([]byte, error) { return []byte(l.String()), nil }
func (l *Level) UnmarshalText(b []byte) error {
	parsed, err := Parse(string(b))
	if err != nil {
		return err
	}
	*l = parsed
	return nil
}

// Parse reads a wire-format taint level. Unknown values fail closed as Hostile:
// a component that cannot understand a taint label must never treat it as safe.
func Parse(s string) (Level, error) {
	switch s {
	case "trusted", "TRUSTED":
		return Trusted, nil
	case "semi", "SEMI":
		return Semi, nil
	case "untrusted", "UNTRUSTED":
		return Untrusted, nil
	case "hostile", "HOSTILE":
		return Hostile, nil
	default:
		return Hostile, fmt.Errorf("taint: unknown level %q (failing closed as hostile)", s)
	}
}

// Valid reports whether l is a defined lattice position.
func (l Level) Valid() bool { return l <= Hostile }

// Join returns the least-distrusting bound of its inputs: max. Propagating
// untrusted content through any operation yields untrusted, forever.
func Join(levels ...Level) Level {
	var out Level
	for _, l := range levels {
		if !l.Valid() {
			return Hostile
		}
		if l > out {
			out = l
		}
	}
	return out
}

// SatisfiesCeiling reports whether l is no more distrusting than ceiling.
// This is the entire authorization check for taint: taint(input) <= ceiling(cap).
func (l Level) SatisfiesCeiling(ceiling Level) bool {
	return l.Valid() && ceiling.Valid() && l <= ceiling
}

// Above reports whether l exceeds ceiling. Used for messages that must explain a
// denial rather than merely make one.
func (l Level) Above(ceiling Level) bool { return !l.SatisfiesCeiling(ceiling) }

// Describe renders the provenance for an approval prompt: the level plus the
// inputs that produced it. Shown to the user verbatim, so it must be readable by
// someone who does not know what taint tracking is.
func (s *Sources) Describe() string { return s.String() }

// JoinStrings parses and joins wire-format levels, failing closed on any error.
func JoinStrings(levels ...string) (Level, error) {
	parsed := make([]Level, 0, len(levels))
	for _, s := range levels {
		l, err := Parse(s)
		if err != nil {
			return Hostile, err
		}
		parsed = append(parsed, l)
	}
	return Join(parsed...), nil
}

// Sources records where a level came from, for approval prompts. A denial the
// user cannot explain is a denial the user will disable.
type Sources struct {
	levels  []Level
	origins []string
}

// NewSources builds an attributed taint provenance record.
func NewSources() *Sources { return &Sources{} }

// Add records one input's level and where it came from.
func (s *Sources) Add(level Level, origin string) *Sources {
	s.levels = append(s.levels, level)
	s.origins = append(s.origins, origin)
	return s
}

// AddAll records an unattributed level, for cases with no single origin.
func (s *Sources) AddAll(level Level) *Sources { return s.Add(level, "") }

// Level returns the join of everything added.
func (s *Sources) Level() Level {
	if s == nil || len(s.levels) == 0 {
		return Trusted
	}
	return Join(s.levels...)
}

// Origins returns the recorded origin strings, de-duplicated, in order.
func (s *Sources) Origins() []string {
	if s == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(s.origins))
	out := make([]string, 0, len(s.origins))
	for _, o := range s.origins {
		if o == "" {
			continue
		}
		if _, ok := seen[o]; ok {
			continue
		}
		seen[o] = struct{}{}
		out = append(out, o)
	}
	return out
}

// SatisfiesCeiling is Sources' view of the same check.
func (s *Sources) SatisfiesCeiling(ceiling Level) bool {
	return s.Level().SatisfiesCeiling(ceiling)
}

// String renders the provenance for an approval prompt: the level plus the
// inputs that produced it. Shown to the user verbatim, so it must be readable
// by someone who does not know what taint tracking is.
func (s *Sources) String() string {
	if s == nil || len(s.levels) == 0 {
		return "trusted (no external inputs)"
	}
	lvl := s.Level()
	out := fmt.Sprintf("%s", lvl)
	if origins := s.Origins(); len(origins) > 0 {
		out += " from "
		for i, o := range origins {
			if i > 0 {
				out += ", "
			}
			out += o
		}
	}
	return out
}
