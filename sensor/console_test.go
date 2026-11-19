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

func TestHeadlessDisplayIdentity(t *testing.T) {
	for _, tc := range []struct {
		name          string
		vendor, model uint32
		want          bool
	}{
		{"observed headless Mac", 0x756e6b6e, 0x76697274, true},
		{"Apple physical display", 0x610, 0x1234, false},
		{"external physical display", 0x10ac, 0x1234, false},
		{"unknown vendor alone", 0x756e6b6e, 0x1234, false},
		{"missing identity", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHeadlessDisplay(tc.vendor, tc.model); got != tc.want {
				t.Fatalf("headless = %t, want %t", got, tc.want)
			}
		})
	}
}
