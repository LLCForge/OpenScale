package trust

import (
	"errors"
	"testing"
)

func TestKnownAnswerTestsPass(t *testing.T) {
	passed, err := KnownAnswerTests()
	if err != nil {
		t.Fatalf("known answer tests: %v", err)
	}
	if len(passed) != len(katCases) {
		t.Fatalf("passed %v, want all %d", passed, len(katCases))
	}
	again, err := CryptoSelfTest()
	if err != nil || len(again) != len(katCases) {
		t.Fatalf("cached self-test: %v %v", again, err)
	}
}

func TestKnownAnswerTestReportsFailure(t *testing.T) {
	saved := katCases
	t.Cleanup(func() { katCases = saved })
	katCases = append([]katCase{{"bozuk", func() error { return errors.New("x") }}}, saved...)
	passed, err := KnownAnswerTests()
	if !errors.Is(err, ErrSelfTest) || len(passed) != 0 {
		t.Fatalf("got %v %v, want ErrSelfTest and nothing passed", passed, err)
	}
}

func BenchmarkKnownAnswerTests(b *testing.B) {
	for b.Loop() {
		if _, err := KnownAnswerTests(); err != nil {
			b.Fatal(err)
		}
	}
}
