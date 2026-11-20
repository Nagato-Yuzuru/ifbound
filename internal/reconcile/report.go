package reconcile

// ReportStep is the step of the report path at which a DNS report
// failed. The zero ReportStep is no step.
type ReportStep uint8

// The steps of the report path.
const (
	// StepTableAdd: the add of the addresses to a table failed.
	StepTableAdd ReportStep = iota + 1
	// StepCommit: the commit of the addresses to the address book failed.
	StepCommit
	// StepLoadedID: the read of the ID of the loaded ruleset failed.
	StepLoadedID
	// StepRuleset: the loaded ruleset is not the installed one.
	StepRuleset
)
