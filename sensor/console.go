package sensor

// ConsoleState describes whether a graphical prompt can be answered locally.
// Unknown state is represented as false, preferring terminal input.
type ConsoleState struct {
	GUIAccess    bool
	OnConsole    bool
	Unlocked     bool
	DisplayAwake bool
}

func (s ConsoleState) Usable() bool {
	return s.GUIAccess && s.OnConsole && s.Unlocked && s.DisplayAwake
}
