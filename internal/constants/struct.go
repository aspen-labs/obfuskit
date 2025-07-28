package constants

type AttackTypes struct {
	All              string
	XSS              string
	SQLi             string
	LFI              string
	RFI              string
	CommandInjection string
	SSRF             string
	XXE              string
}

type Encodings struct {
	All     string
	URI     string
	Base64  string
	Hex     string
	HTML    string
	Special string
}

type Evasions struct {
	All       string
	Encodings string
	Paths     string
	Commands  string
}

type Level string

const (
	Basic    Level = "Basic"
	Medium   Level = "Medium"
	Advanced Level = "Advanced"
)
