package sensor

import "testing"

func TestConsoleUsable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state ConsoleState
		want  bool
	}{
		{"awake unlocked console", ConsoleState{true, true, true, true}, true},
		{"locked", ConsoleState{true, true, false, true}, false},
		{"display asleep", ConsoleState{true, true, true, false}, false},
		{"inactive session", ConsoleState{true, false, true, true}, false},
		{"no graphical access", ConsoleState{false, true, true, true}, false},
		{"unknown", ConsoleState{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.Usable(); got != tc.want {
				t.Fatalf("Usable() = %t, want %t", got, tc.want)
			}
		})
	}
}
