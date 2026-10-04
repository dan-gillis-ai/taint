// Conformance test for the shared taint vectors.
//
// This is the most important test in the repository. The Go implementation is
// the enforcement point in the device agent; the Python implementation does the
// labelling. If they diverge, one of the two security controls silently stops
// working, and no single-language test would catch it.
//
// Run with:  go test ./libs/taint/go/
package taint_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dan-gillis-ai/taint"
)

type vectors struct {
	Levels []struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	} `json:"levels"`
	JoinCases []struct {
		Name   string   `json:"name"`
		Inputs []string `json:"inputs"`
		Expect string   `json:"expect"`
	} `json:"join_cases"`
	CeilingCases []struct {
		Name      string `json:"name"`
		Taint     string `json:"taint"`
		Ceiling   string `json:"ceiling"`
		Satisfies bool   `json:"satisfies"`
	} `json:"ceiling_cases"`
	ParseCases []struct {
		Name   string `json:"name"`
		Input  string `json:"input"`
		Expect string `json:"expect"`
	} `json:"parse_cases"`
	InvariantCases []struct {
		Name  string `json:"name"`
		Why   string `json:"why"`
		Steps []struct {
			Op      string `json:"op"`
			Level   string `json:"level"`
			Origin  string `json:"origin"`
			Ceiling string `json:"ceiling"`
		} `json:"steps"`
		ExpectLevel     string `json:"expect_level"`
		ExpectSatisfies *bool  `json:"expect_satisfies"`
	} `json:"invariant_cases"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	// vectors.json sits one level up from go/
	path := filepath.Join("..", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.InvariantCases) == 0 {
		t.Fatal("vectors.json has no invariant cases; refusing to pass a vacuous conformance test")
	}
	return v
}

func TestLevelOrderingMatchesVectors(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.Levels {
		parsed, err := taint.Parse(tc.Name)
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.Name, err)
		}
		if int(parsed) != tc.Value {
			t.Errorf("%s: got value %d, want %d", tc.Name, int(parsed), tc.Value)
		}
	}
	// Ordering must be strictly ascending or every ceiling check is a lie.
	for i := 1; i < len(taint.AllLevels); i++ {
		if taint.AllLevels[i] <= taint.AllLevels[i-1] {
			t.Fatalf("lattice is not strictly ascending at index %d", i)
		}
	}
}

func TestJoinConformance(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.JoinCases {
		t.Run(tc.Name, func(t *testing.T) {
			levels := make([]taint.Level, 0, len(tc.Inputs))
			for _, in := range tc.Inputs {
				l, err := taint.Parse(in)
				if err != nil {
					t.Fatalf("parse input %q: %v", in, err)
				}
				levels = append(levels, l)
			}
			if got := taint.Join(levels...).String(); got != tc.Expect {
				t.Errorf("join(%v) = %q, want %q", tc.Inputs, got, tc.Expect)
			}
		})
	}
}

func TestCeilingConformance(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.CeilingCases {
		t.Run(tc.Name, func(t *testing.T) {
			lvl, err := taint.Parse(tc.Taint)
			if err != nil {
				t.Fatalf("parse taint: %v", err)
			}
			ceil, err := taint.Parse(tc.Ceiling)
			if err != nil {
				t.Fatalf("parse ceiling: %v", err)
			}
			if got := lvl.SatisfiesCeiling(ceil); got != tc.Satisfies {
				t.Errorf("taint(%s).satisfies_ceiling(%s) = %v, want %v",
					tc.Taint, tc.Ceiling, got, tc.Satisfies)
			}
			// Above must be the exact complement, or error messages will lie.
			if lvl.Above(ceil) == tc.Satisfies {
				t.Errorf("above(%s) = %v, want %v (complement of satisfies)",
					tc.Ceiling, lvl.Above(ceil), !tc.Satisfies)
			}
		})
	}
}

// Fails closed is the load-bearing property here: an unparseable label must
// escalate to Hostile, never fall back to Trusted.
func TestParseConformance(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.ParseCases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := taint.Parse(tc.Input)
			if err != nil {
				// Parse returning an error is acceptable only if the error
				// still yields a usable, maximally-distrusting value.
				if got != taint.Hostile {
					t.Errorf("parse(%q) errored but returned %v, want hostile", tc.Input, got)
				}
				return
			}
			if got.String() != tc.Expect {
				t.Errorf("parse(%q) = %q, want %q", tc.Input, got, tc.Expect)
			}
			if !strings.HasPrefix(tc.Input, strings.ToLower(tc.Expect)) && tc.Expect == "hostile" {
				t.Logf("parse(%q) returned %v (expected fail-closed path)", tc.Input, got)
			}
		})
	}
}

func TestInvariantConformance(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.InvariantCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Logf("why: %s", tc.Why)
			sources := taint.NewSources()
			for _, step := range tc.Steps {
				switch step.Op {
				case "label":
					lvl, err := taint.Parse(step.Level)
					if err != nil {
						t.Fatalf("parse level: %v", err)
					}
					sources.Add(lvl, step.Origin)
				case "join":
					// no-op; level is derived on demand
				case "check_ceiling":
					ceil, err := taint.Parse(step.Ceiling)
					if err != nil {
						t.Fatalf("parse ceiling: %v", err)
					}
					want := tc.ExpectSatisfies
					if want == nil {
						continue
					}
					if got := sources.SatisfiesCeiling(ceil); got != *want {
						t.Errorf("satisfies_ceiling(%s) = %v, want %v", step.Ceiling, got, *want)
					}
				default:
					t.Fatalf("unknown op %q", step.Op)
				}
			}
			if got := sources.Level().String(); got != tc.ExpectLevel {
				t.Errorf("effective level = %q, want %q", got, tc.ExpectLevel)
			}
		})
	}
}

func TestEmptySourcesIsTrusted(t *testing.T) {
	if got := taint.NewSources().Level(); got != taint.Trusted {
		t.Errorf("empty sources = %v, want trusted", got)
	}
}

func TestSourcesDescribeIsHumanReadable(t *testing.T) {
	s := taint.NewSources().
		Add(taint.Semi, "model.generation").
		Add(taint.Untrusted, "https://example.com/issue/42").
		Add(taint.Untrusted, "https://example.com/issue/42") // duplicate

	got := s.Describe()
	if !strings.Contains(got, "untrusted") {
		t.Errorf("describe() = %q, want it to mention the joined level", got)
	}
	if !strings.Contains(got, "https://example.com/issue/42") {
		t.Errorf("describe() = %q, want it to show the taint origin", got)
	}
	if strings.Count(got, "issue/42") != 1 {
		t.Errorf("describe() = %q, want duplicate origins de-duplicated", got)
	}
}

func TestInvalidLevelFailsClosed(t *testing.T) {
	// An out-of-range value must not be treated as trusted.
	var bad taint.Level = 200
	if bad.SatisfiesCeiling(taint.Hostile) {
		t.Error("out-of-range level satisfied a ceiling; must fail closed")
	}
	if got := taint.Join(bad); got != taint.Hostile {
		t.Errorf("join(out-of-range) = %v, want hostile", got)
	}
}
