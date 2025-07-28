package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"obfuskit/internal/evasions/command"
	"obfuskit/internal/evasions/encoders"
	"obfuskit/internal/evasions/path"
	"obfuskit/types"
)

var EvasionFunctions = map[types.PayloadEncoding]func(string, types.EvasionLevel) []string{
	types.PayloadEncodingBase64: func(payload string, level types.EvasionLevel) []string {
		return encoders.Base64Variants(payload, level)
	},
	types.PayloadEncodingBestFit: func(payload string, level types.EvasionLevel) []string {
		return encoders.BestFitVariants(payload, level)
	},
	types.PayloadEncodingHex: func(payload string, level types.EvasionLevel) []string {
		return encoders.HexVariants(payload, level)
	},
	types.PayloadEncodingHTML: func(payload string, level types.EvasionLevel) []string {
		return encoders.HTMLVariants(payload, level)
	},
	types.PayloadEncodingOctal: func(payload string, level types.EvasionLevel) []string {
		return encoders.OctalVariants(payload, level)
	},
	types.PayloadEncodingUnicode: func(payload string, level types.EvasionLevel) []string {
		return encoders.UnicodeVariants(payload, level)
	},
	types.PayloadEncodingUnixCmd: func(payload string, level types.EvasionLevel) []string {
		return command.UnixCmdVariants(payload, level)
	},
	types.PayloadEncodingWindowsCmd: func(payload string, level types.EvasionLevel) []string {
		return command.WindowsCmdVariants(payload, level)
	},
	types.PayloadEncodingPathTraversal: func(payload string, level types.EvasionLevel) []string {
		return path.PathTraversalVariants(payload, level)
	},
	// TODO: Add more evasion functions
	// Pending URL, DoubleURL, MixedCase, UTF8
}

var PayloadEvasionMap = map[types.AttackType][]types.PayloadEncoding{
	types.AttackTypeXSS: {
		types.PayloadEncodingHTML,
		types.PayloadEncodingUnicode,
		types.PayloadEncodingHex,
		types.PayloadEncodingOctal,
		types.PayloadEncodingBase64,
		types.PayloadEncodingBestFit,
	},
	types.AttackTypeSQLI: {
		types.PayloadEncodingUnixCmd,
		types.PayloadEncodingUnicode,
		types.PayloadEncodingHex,
		types.PayloadEncodingOctal,
		types.PayloadEncodingBase64,
		types.PayloadEncodingBestFit,
	},
	types.AttackTypeUnixCMDI: {
		types.PayloadEncodingUnixCmd,
		types.PayloadEncodingUnicode,
		types.PayloadEncodingHex,
		types.PayloadEncodingOctal,
		types.PayloadEncodingBase64,
		types.PayloadEncodingBestFit,
		types.PayloadEncodingPathTraversal,
	},
	types.AttackTypeWinCMDI: {
		types.PayloadEncodingWindowsCmd,
		types.PayloadEncodingUnicode,
		types.PayloadEncodingHex,
		types.PayloadEncodingOctal,
		types.PayloadEncodingBase64,
		types.PayloadEncodingBestFit,
		types.PayloadEncodingPathTraversal,
	},
	types.AttackTypePath: {
		types.PayloadEncodingPathTraversal,
		types.PayloadEncodingUnicode,
		types.PayloadEncodingHex,
		types.PayloadEncodingOctal,
		types.PayloadEncodingBase64,
		types.PayloadEncodingBestFit,
	},
	types.AttackTypeFileAccess: {
		types.PayloadEncodingPathTraversal,
		types.PayloadEncodingUnicode,
		types.PayloadEncodingHex,
		types.PayloadEncodingOctal,
		types.PayloadEncodingBase64,
		types.PayloadEncodingBestFit,
	},
	types.AttackTypeLDAP: {
		types.PayloadEncodingUnicode,
		types.PayloadEncodingHex,
		types.PayloadEncodingOctal,
		types.PayloadEncodingBase64,
		types.PayloadEncodingBestFit,
	},
	types.AttackTypeGeneric: {
		types.PayloadEncodingHTML,
		types.PayloadEncodingUnicode,
		types.PayloadEncodingHex,
		types.PayloadEncodingOctal,
		types.PayloadEncodingBase64,
		types.PayloadEncodingBestFit,
		types.PayloadEncodingUnixCmd,
		types.PayloadEncodingWindowsCmd,
		types.PayloadEncodingPathTraversal,
	},
}

var EvasionCategoryMap = map[types.PayloadEncoding]types.EvasionCategory{
	types.PayloadEncodingHTML:          types.EvasionCategoryEncoder,
	types.PayloadEncodingUnicode:       types.EvasionCategoryEncoder,
	types.PayloadEncodingHex:           types.EvasionCategoryEncoder,
	types.PayloadEncodingOctal:         types.EvasionCategoryEncoder,
	types.PayloadEncodingBase64:        types.EvasionCategoryEncoder,
	types.PayloadEncodingBestFit:       types.EvasionCategoryEncoder,
	types.PayloadEncodingURL:           types.EvasionCategoryEncoder,
	types.PayloadEncodingDoubleURL:     types.EvasionCategoryEncoder,
	types.PayloadEncodingMixedCase:     types.EvasionCategoryEncoder,
	types.PayloadEncodingUTF8:          types.EvasionCategoryEncoder,
	types.PayloadEncodingUnixCmd:       types.EvasionCategoryCommand,
	types.PayloadEncodingWindowsCmd:    types.EvasionCategoryCommand,
	types.PayloadEncodingPathTraversal: types.EvasionCategoryPath,
}

func GetEvasionsForPayload(attackType types.AttackType) ([]types.PayloadEncoding, bool) {
	evasions, exists := PayloadEvasionMap[attackType]
	return evasions, exists
}

func GetEvasionsByCategory(attackType types.AttackType) map[types.EvasionCategory][]types.PayloadEncoding {
	evasions, exists := PayloadEvasionMap[attackType]
	if !exists {
		return nil
	}
	categorized := make(map[types.EvasionCategory][]types.PayloadEncoding)
	for _, evasion := range evasions {
		category := EvasionCategoryMap[evasion]
		categorized[category] = append(categorized[category], evasion)
	}
	return categorized
}

func IsEvasionApplicable(payloadType types.AttackType, evasionType types.PayloadEncoding) bool {
	evasions, exists := PayloadEvasionMap[payloadType]
	if !exists {
		return false
	}

	for _, evasion := range evasions {
		if evasion == evasionType {
			return true
		}
	}
	return false
}

func ApplyEvasion(payload string, evasionType types.PayloadEncoding, level types.EvasionLevel) ([]string, error) {
	if payload == "" {
		return nil, nil
	}

	evasionFunc, exists := EvasionFunctions[evasionType]
	if !exists {
		return nil, fmt.Errorf("evasion function %q not found", evasionType)
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in %s: %v\n", evasionType, r)
		}
	}()

	return evasionFunc(payload, level), nil
}

func ApplyEvasionsToPayload(payload string, attackType types.AttackType, level types.EvasionLevel) map[types.PayloadEncoding][]string {
	if payload == "" || attackType == "" {
		return nil
	}

	evasions, exists := GetEvasionsForPayload(attackType)
	if !exists {
		return nil
	}

	results := make(map[types.PayloadEncoding][]string, len(evasions))
	for _, evasionType := range evasions {
		variants, err := ApplyEvasion(payload, evasionType, level)
		if err != nil {
			results[evasionType] = []string{fmt.Sprintf("Error: %v", err)}
			continue
		}
		if len(variants) > 0 {
			results[evasionType] = variants
		}
	}

	return results
}

func GetAllAttackTypes() []types.AttackType {
	types := make([]types.AttackType, 0, len(PayloadEvasionMap))
	for payloadType := range PayloadEvasionMap {
		types = append(types, payloadType)
	}
	sort.Slice(types, func(i, j int) bool {
		return types[i] < types[j]
	})
	return types
}

func PrintPayloadEvasionMap() {
	attackTypes := GetAllAttackTypes()

	fmt.Println("Payload to Evasions Mapping:")
	fmt.Println("============================")

	for _, attackType := range attackTypes {
		fmt.Printf("\n%s:\n", attackType)
		categorized := GetEvasionsByCategory(attackType)

		for category, evasions := range categorized {
			fmt.Printf("  %s:\n", category)
			for _, evasion := range evasions {
				fmt.Printf("    - %s\n", evasion)
			}
		}
	}
}

// UI Types and structures
type item struct {
	title any
	desc  string
}

func (i item) Title() string       { return i.title.(string) }
func (i item) Description() string { return i.desc }
func (i item) FilterValue() string { return i.title.(string) }

var (
	mainMenuItems = []list.Item{
		item{types.ActionGeneratePayloads, "Generate and view possible attack payloads"},
		item{types.ActionSendToURL, "Generate payloads and send them to a test URL"},
		item{types.ActionUseExistingPayloads, "Give a path or enter a list of payloads"},
	}

	attackItems = []list.Item{
		item{"I'll pick", "Choose a specific attack type"},
		item{"All", "Use all available attack types"},
	}

	specificAttackItems = []list.Item{
		item{types.AttackTypeXSS, "Cross Site Scripting"},
		item{types.AttackTypeSQLI, "SQL Injection"},
		item{types.AttackTypeUnixCMDI, "Local File Inclusion"},
		item{types.AttackTypeWinCMDI, "Remote File Inclusion"},
		item{types.AttackTypeOsCMDI, "OS Command Injection"},
		item{types.AttackTypeSSRF, "Server-Side Request Forgery"},
		item{types.AttackTypeXXE, "XML External Entity"},
	}

	payloadItems = []list.Item{
		item{"I'll pick", "Choose a specific payload evasion method"},
		item{"All", "Use all available payload evasion methods"},
	}

	specificPayloadItems = []list.Item{
		item{types.PayloadMethodEncodings, "Generate payloads with various encodings"},
		item{types.PayloadMethodFile, "Generate payloads with various path structures"},
		item{types.PayloadMethodEnterManually, "Generate payloads with various command structures"},
	}

	encodingItems = []list.Item{
		item{types.PayloadEncodingURL, "Encode payloads using URL encoding (%20, %3C, etc.)"},
		item{types.PayloadEncodingHTML, "Encode payloads using HTML entities (&lt;, &gt;, etc.)"},
		item{types.PayloadEncodingUnicode, "Encode payloads using Unicode escape sequences"},
		item{types.PayloadEncodingBase64, "Encode payloads using Base64 encoding"},
		item{types.PayloadEncodingHex, "Encode payloads using hexadecimal encoding"},
		item{types.PayloadEncodingDoubleURL, "Apply URL encoding twice"},
		item{types.PayloadEncodingMixedCase, "Use mixed case characters in payloads"},
		item{types.PayloadEncodingUTF8, "Use UTF-8 byte sequences"},
	}

	evasionLevelItems = []list.Item{
		item{types.EvasionLevelBasic, "Use simple evasion techniques (fastest, fewer variants)"},
		item{types.EvasionLevelMedium, "Use moderate evasion techniques (balanced approach)"},
		item{types.EvasionLevelAdvanced, "Use all available evasion techniques (comprehensive, more variants)"},
	}

	payloadSourceItems = []list.Item{
		item{types.PayloadSourceFromFile, "Load payloads from a text file"},
		item{types.PayloadSourceEnterManually, "Enter payloads manually in the terminal"},
	}

	targetItems = []list.Item{
		item{"Specify URL", "Enter a specific target URL"},
		item{"Save to file", "Save payloads to a file instead of targeting a URL"},
	}

	reportItems = []list.Item{
		item{"I'll pick", "Choose a specific report format"},
		item{types.ReportTypeAll, "Generate reports in all available formats"},
	}

	specificReportItems = []list.Item{
		item{types.ReportTypeHTML, "Generate a formatted HTML Report"},
		item{types.ReportTypePretty, "Generate a formatted report in the terminal"},
		item{types.ReportTypePDF, "Generate a PDF document report"},
		item{types.ReportTypeCSV, "Generate data in CSV format"},
		item{types.ReportTypeNuclei, "Generate nuclei YAML templates for automated scanning"},
		item{types.ReportTypeJSON, "Generate data in JSON format"},
	}
)

// state represents the current state of the UI
type state int

const (
	stateMainMenu state = iota
	stateChooseAttackMethod
	stateChooseSpecificAttack
	stateChoosePayloadMethod
	stateChooseSpecificPayload
	stateChooseEncoding
	stateChooseEvasionLevel
	stateChoosePayloadSource
	stateEnterFilePath
	stateEnterPayloads
	stateChooseTargetMethod
	stateEnterURL
	stateChooseReportMethod
	stateChooseSpecificReport
	stateDone
)

// Model represents the application state
type Model struct {
	list                  list.Model
	textInput             textinput.Model
	current               state
	SelectedAction        types.Action
	SelectedAttackType    types.AttackType
	SelectedPayloadMethod types.PayloadMethod
	SelectedEncoding      types.PayloadEncoding
	SelectedEvasionLevel  types.EvasionLevel
	SelectedPayloadSource types.PayloadSource
	CustomPayloads        []string
	PayloadFilePath       string
	SelectedTargetMethod  types.TargetMethod
	SelectedReportType    types.ReportType
	URL                   string
	ready                 bool
	autoAttack            bool
	autoPayload           bool
	autoReport            bool
	isEnteringPayloads    bool
	payloadInputBuffer    string
}

// initialModel creates the initial model state
func initialModel() Model {
	l := list.New(mainMenuItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Select what you want to do:"

	ti := textinput.New()
	ti.Placeholder = "Enter URL (e.g., https://example.com)"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 50

	return Model{
		list:      l,
		textInput: ti,
		current:   stateMainMenu,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.EnterAltScreen
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if !m.ready {
			m.list.SetSize(msg.Width, msg.Height-2)
			m.ready = true
		}
		return m, nil

	case tea.KeyMsg:
		// Handle text input states
		if m.current == stateEnterURL || m.current == stateEnterFilePath || m.current == stateEnterPayloads {
			switch msg.String() {
			case "enter":
				value := strings.TrimSpace(m.textInput.Value())
				if value != "" {
					switch m.current {
					case stateEnterURL:
						m.URL = value
						m.list.SetItems(reportItems)
						m.list.Title = "Choose report format:"
						m.current = stateChooseReportMethod
					case stateEnterFilePath:
						m.PayloadFilePath = value
						m.list.SetItems(targetItems)
						m.list.Title = "Choose target method:"
						m.current = stateChooseTargetMethod
					case stateEnterPayloads:
						if !m.isEnteringPayloads {
							// First payload entered, switch to multi-line mode
							m.isEnteringPayloads = true
							m.CustomPayloads = append(m.CustomPayloads, value)
							m.textInput.SetValue("")
							m.textInput.Placeholder = "Enter next payload (or 'done' to finish)"
						} else if value == "done" {
							// Finished entering payloads
							m.list.SetItems(targetItems)
							m.list.Title = "Choose target method:"
							m.current = stateChooseTargetMethod
						} else {
							// Add another payload
							m.CustomPayloads = append(m.CustomPayloads, value)
							m.textInput.SetValue("")
						}
					}
				}
				return m, nil
			case "esc":
				switch m.current {
				case stateEnterURL:
					m.list.SetItems(targetItems)
					m.list.Title = "Choose target method:"
					m.current = stateChooseTargetMethod
				case stateEnterFilePath, stateEnterPayloads:
					m.list.SetItems(payloadSourceItems)
					m.list.Title = "How do you want to provide payloads?"
					m.current = stateChoosePayloadSource
				}
				return m, nil
			case "ctrl+c", "q":
				return m, tea.Quit
			default:
				var cmd tea.Cmd
				m.textInput, cmd = m.textInput.Update(msg)
				return m, cmd
			}
		}

		// Handle other states
		switch msg.String() {
		case "enter":
			return m.handleEnterKey()
		case "ctrl+c", "q":
			return m, tea.Quit
		case "esc":
			return m.handleEscKey()
		}
	}

	// Update list for non-text input states
	if m.current != stateEnterURL && m.current != stateEnterFilePath && m.current != stateEnterPayloads {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) handleEnterKey() (tea.Model, tea.Cmd) {
	switch m.current {
	case stateMainMenu:
		selected := m.list.SelectedItem().(item).title
		m.SelectedAction = selected.(types.Action)

		// Handle "Use Existing Payloads" differently
		if selected == types.ActionUseExistingPayloads {
			m.list.SetItems(payloadSourceItems)
			m.list.Title = "How do you want to provide payloads?"
			m.current = stateChoosePayloadSource
		} else {
			m.list.SetItems(attackItems)
			m.list.Title = "Choose attack type:"
			m.current = stateChooseAttackMethod
		}

	case stateChooseAttackMethod:
		if m.list.SelectedItem().(item).title == "I'll pick" {
			m.autoAttack = false
			m.list.SetItems(specificAttackItems)
			m.list.Title = "Choose specific attack type:"
			m.current = stateChooseSpecificAttack
		} else {
			m.autoAttack = true
			m.SelectedAttackType = types.AttackTypeGeneric
			m.list.SetItems(payloadItems)
			m.list.Title = "Choose payload method:"
			m.current = stateChoosePayloadMethod
		}

	case stateChooseSpecificAttack:
		m.SelectedAttackType = m.list.SelectedItem().(item).title.(types.AttackType)
		m.list.SetItems(payloadItems)
		m.list.Title = "Choose payload evasion method:"
		m.current = stateChoosePayloadMethod

	case stateChoosePayloadMethod:
		if m.list.SelectedItem().(item).title == "I'll pick" {
			m.autoPayload = false
			m.list.SetItems(specificPayloadItems)
			m.list.Title = "Choose specific payload evasion method:"
			m.current = stateChooseSpecificPayload
		} else {
			m.autoPayload = true
			m.SelectedPayloadMethod = types.PayloadMethodAuto
			// Set default payload source when auto-selecting
			m.SelectedPayloadSource = types.PayloadSourceGenerated
			// Always go through evasion level selection
			m.list.SetItems(evasionLevelItems)
			m.list.Title = "Choose evasion level:"
			m.current = stateChooseEvasionLevel
		}

	case stateChooseSpecificPayload:
		selected := m.list.SelectedItem().(item).title
		m.SelectedPayloadMethod = selected.(types.PayloadMethod)

		if selected == types.PayloadMethodEncodings {
			// Show encoding options
			m.list.SetItems(encodingItems)
			m.list.Title = "Choose encoding method:"
			m.current = stateChooseEncoding
		} else {
			// For other payload types, go to evasion level selection
			m.list.SetItems(evasionLevelItems)
			m.list.Title = "Choose evasion level:"
			m.current = stateChooseEvasionLevel
		}

	case stateChooseEncoding:
		m.SelectedEncoding = m.list.SelectedItem().(item).title.(types.PayloadEncoding)
		m.list.SetItems(evasionLevelItems)
		m.list.Title = "Choose evasion level:"
		m.current = stateChooseEvasionLevel

	case stateChooseEvasionLevel:
		m.SelectedEvasionLevel = m.list.SelectedItem().(item).title.(types.EvasionLevel)
		if m.autoPayload {
			// In auto payload mode, go directly to target selection
			m.list.SetItems(targetItems)
			m.list.Title = "Choose target method:"
			m.current = stateChooseTargetMethod
		} else {
			// In manual payload mode, go to payload source selection
			m.list.SetItems(payloadSourceItems)
			m.list.Title = "How do you want to provide payloads?"
			m.current = stateChoosePayloadSource
		}

	case stateChoosePayloadSource:
		selected := m.list.SelectedItem().(item).title
		m.SelectedPayloadSource = selected.(types.PayloadSource)

		if selected == types.PayloadSourceFromFile {
			m.textInput.Placeholder = "Enter file path (e.g., payloads.txt)"
			m.textInput.SetValue("")
			m.current = stateEnterFilePath
		} else {
			m.textInput.Placeholder = "Enter your first payload"
			m.textInput.SetValue("")
			m.isEnteringPayloads = false
			m.CustomPayloads = []string{}
			m.current = stateEnterPayloads
		}

	case stateChooseTargetMethod:
		if m.list.SelectedItem().(item).title == "Specify URL" {
			m.SelectedTargetMethod = types.TargetMethodURL
			m.current = stateEnterURL
		} else {
			m.SelectedTargetMethod = types.TargetMethodFile
			m.URL = "output.txt"
			m.list.SetItems(reportItems)
			m.list.Title = "Choose report format:"
			m.current = stateChooseReportMethod
		}

	case stateChooseReportMethod:
		if m.list.SelectedItem().(item).title == "I'll pick" {
			m.autoReport = false
			m.list.SetItems(specificReportItems)
			m.list.Title = "Choose specific report format:"
			m.current = stateChooseSpecificReport
		} else {
			m.autoReport = true
			m.SelectedReportType = "All"
			m.current = stateDone
			return m, tea.Quit
		}

	case stateChooseSpecificReport:
		m.SelectedReportType = m.list.SelectedItem().(item).title.(types.ReportType)
		m.current = stateDone
		return m, tea.Quit
	}

	return m, nil
}

func (m Model) handleEscKey() (tea.Model, tea.Cmd) {
	switch m.current {
	case stateChooseAttackMethod:
		m.list.SetItems(mainMenuItems)
		m.list.Title = "Select what you want to do:"
		m.current = stateMainMenu
	case stateChooseSpecificAttack:
		m.list.SetItems(attackItems)
		m.list.Title = "Choose attack type:"
		m.current = stateChooseAttackMethod
	case stateChoosePayloadMethod:
		if m.autoAttack {
			m.list.SetItems(attackItems)
			m.list.Title = "Choose attack type:"
			m.current = stateChooseAttackMethod
		} else {
			m.list.SetItems(specificAttackItems)
			m.list.Title = "Choose specific attack type:"
			m.current = stateChooseSpecificAttack
		}
	case stateChoosePayloadSource:
		// Handle back navigation from payload source selection
		if m.SelectedAction == types.ActionUseExistingPayloads {
			m.list.SetItems(mainMenuItems)
			m.list.Title = "Select what you want to do:"
			m.current = stateMainMenu
		} else if m.SelectedPayloadMethod == types.PayloadMethodEncodings {
			m.list.SetItems(encodingItems)
			m.list.Title = "Choose encoding method:"
			m.current = stateChooseEncoding
		} else if m.autoPayload {
			m.list.SetItems(payloadItems)
			m.list.Title = "Choose payload method:"
			m.current = stateChoosePayloadMethod
		} else {
			m.list.SetItems(specificPayloadItems)
			m.list.Title = "Choose specific payload evasion method:"
			m.current = stateChooseSpecificPayload
		}
	// Add more back navigation as needed
	default:
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) View() string {
	switch m.current {
	case stateEnterURL:
		return fmt.Sprintf(
			"Enter target URL:\n\n%s\n\n%s",
			m.textInput.View(),
			"(Press Enter to confirm, Esc to go back)",
		)
	case stateEnterFilePath:
		return fmt.Sprintf(
			"Enter payload file path:\n\n%s\n\n%s",
			m.textInput.View(),
			"(Press Enter to confirm, Esc to go back)",
		)
	case stateEnterPayloads:
		var display strings.Builder
		display.WriteString("Enter payloads manually:\n\n")

		if len(m.CustomPayloads) > 0 {
			display.WriteString("Payloads entered so far:\n")
			for i, payload := range m.CustomPayloads {
				display.WriteString(fmt.Sprintf("%d. %s\n", i+1, payload))
			}
			display.WriteString("\n")
		}

		display.WriteString(m.textInput.View())
		display.WriteString("\n\n")

		if m.isEnteringPayloads {
			display.WriteString("(Enter 'done' to finish, or enter another payload)")
		} else {
			display.WriteString("(Press Enter to add payload, Esc to go back)")
		}

		return display.String()
	case stateDone:
		summary := fmt.Sprintf(`
Configuration Summary:
=====================
Main Action    : %s
Attack Type    : %s %s
Evasion Method : %s %s`,
			string(m.SelectedAction),
			string(m.SelectedAttackType), autoString(m.autoAttack),
			string(m.SelectedPayloadMethod), autoString(m.autoPayload))

		if m.SelectedEncoding != "" {
			summary += fmt.Sprintf("\nEncoding       : %s", m.SelectedEncoding)
		}

		if m.SelectedEvasionLevel != "" {
			summary += fmt.Sprintf("\nEvasion Level  : %s", m.SelectedEvasionLevel)
		}

		if m.SelectedPayloadSource != "" {
			summary += fmt.Sprintf("\nPayload Source : %s", m.SelectedPayloadSource)
			if m.SelectedPayloadSource == types.PayloadSourceFromFile && m.PayloadFilePath != "" {
				summary += fmt.Sprintf(" (%s)", m.PayloadFilePath)
			} else if m.SelectedPayloadSource == types.PayloadSourceEnterManually && len(m.CustomPayloads) > 0 {
				summary += fmt.Sprintf(" (%d payloads)", len(m.CustomPayloads))
			}
		}

		summary += fmt.Sprintf(`
Target         : %s (%s)
Report Type    : %s %s

Press any key to exit...`,
			string(m.SelectedTargetMethod), m.URL,
			string(m.SelectedReportType), autoString(m.autoReport))

		return summary
	default:
		return m.list.View() + "\n\n(Press 'q' to quit, 'esc' to go back)"
	}
}

func autoString(auto bool) string {
	if auto {
		return "(all selected)"
	}
	return ""
}

// Global variable to store the final selection
var FinalSelection Model

// GetInteractiveCmd returns the interactive command
func GetInteractiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "interactive",
		Short: "Interactive terminal UI for selecting payload generation options",
		Long: `Launch an interactive terminal interface to configure payload generation options.
This tool allows you to select attack types, evasion methods, targets, and report formats
through an intuitive menu-driven interface.`,
		Run: runInteractive,
	}
}

func runInteractive(cmd *cobra.Command, args []string) {
	selection, err := RunInteractiveUI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	displayFinalConfiguration(selection)
}

// displayFinalConfiguration shows the final configuration to the user
func displayFinalConfiguration(m Model) {
	if m.current == stateDone {
		fmt.Println("\n" + strings.Repeat("=", 50))
		fmt.Println("FINAL CONFIGURATION")
		fmt.Println(strings.Repeat("=", 50))
		fmt.Printf("Main Action    : %s\n", m.SelectedAction)
		fmt.Printf("Attack Type    : %s %s\n", m.SelectedAttackType, autoString(m.autoAttack))
		fmt.Printf("Evasion Method : %s %s\n", m.SelectedPayloadMethod, autoString(m.autoPayload))

		if m.SelectedEncoding != "" {
			fmt.Printf("Encoding       : %s\n", m.SelectedEncoding)
		}

		if m.SelectedEvasionLevel != "" {
			fmt.Printf("Evasion Level  : %s\n", m.SelectedEvasionLevel)
		}

		if m.SelectedPayloadSource != "" {
			fmt.Printf("Payload Source : %s", m.SelectedPayloadSource)
			if m.SelectedPayloadSource == types.PayloadSourceFromFile && m.PayloadFilePath != "" {
				fmt.Printf(" (%s)", m.PayloadFilePath)
			} else if m.SelectedPayloadSource == types.PayloadSourceEnterManually && len(m.CustomPayloads) > 0 {
				fmt.Printf(" (%d payloads)", len(m.CustomPayloads))
			}
			fmt.Println()
		}

		if len(m.CustomPayloads) > 0 {
			fmt.Println("Custom Payloads:")
			for i, payload := range m.CustomPayloads {
				fmt.Printf("  %d. %s\n", i+1, payload)
			}
		}

		fmt.Printf("Target         : %s (%s)\n", m.SelectedTargetMethod, m.URL)
		fmt.Printf("Report Type    : %s %s\n", m.SelectedReportType, autoString(m.autoReport))
		fmt.Println(strings.Repeat("=", 50))
	}
}

// RunInteractiveUI runs the interactive UI and returns the final selection
func RunInteractiveUI() (Model, error) {
	p := tea.NewProgram(initialModel())
	finalModel, err := p.Run()
	if err != nil {
		return Model{}, fmt.Errorf("error running interactive UI: %w", err)
	}

	m, ok := finalModel.(Model)
	if !ok {
		return Model{}, fmt.Errorf("unexpected model type")
	}

	// Store the selection globally for backward compatibility
	FinalSelection = m

	// Validate the selection
	if err := ValidateSelection(m); err != nil {
		return Model{}, fmt.Errorf("invalid selection: %w", err)
	}

	return m, nil
}

func GetFinalSelection() Model {
	if FinalSelection.current != stateDone {
		selection, err := RunInteractiveUI()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return selection
	}
	return FinalSelection
}

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error in %s: %s", e.Field, e.Message)
}

func ValidateSelection(m Model) error {
	if m.SelectedAction == "" {
		return ValidationError{Field: "SelectedAction", Message: "main action is required"}
	}

	if m.SelectedAction == types.ActionUseExistingPayloads {
		if m.SelectedPayloadSource == "" {
			return ValidationError{Field: "SelectedPayloadSource", Message: "payload source is required"}
		}
		if m.SelectedPayloadSource == types.PayloadSourceFromFile && strings.TrimSpace(m.PayloadFilePath) == "" {
			return ValidationError{Field: "PayloadFilePath", Message: "file path is required when using file source"}
		}
		if m.SelectedPayloadSource == types.PayloadSourceEnterManually && len(m.CustomPayloads) == 0 {
			return ValidationError{Field: "CustomPayloads", Message: "at least one payload is required when entering manually"}
		}
	} else {
		if m.SelectedAttackType == "" {
			return ValidationError{Field: "SelectedAttackType", Message: "attack type is required"}
		}
		if m.SelectedPayloadMethod == "" {
			return ValidationError{Field: "SelectedPayloadMethod", Message: "payload method is required"}
		}
		if m.SelectedPayloadMethod == types.PayloadMethodEncodings && m.SelectedEncoding == "" {
			return ValidationError{Field: "SelectedEncoding", Message: "encoding method is required when using encodings"}
		}

		if !m.autoPayload && m.SelectedPayloadSource == "" {
			return ValidationError{Field: "SelectedPayloadSource", Message: "payload source is required"}
		}
		if m.SelectedPayloadSource == "From File" && strings.TrimSpace(m.PayloadFilePath) == "" {
			return ValidationError{Field: "PayloadFilePath", Message: "file path is required when using file source"}
		}
		if m.SelectedPayloadSource == "Enter Manually" && len(m.CustomPayloads) == 0 {
			return ValidationError{Field: "CustomPayloads", Message: "at least one payload is required when entering manually"}
		}
	}

	if m.SelectedTargetMethod == "" {
		return ValidationError{Field: "SelectedTargetMethod", Message: "target method is required"}
	}
	if m.SelectedTargetMethod == types.TargetMethodURL && strings.TrimSpace(m.URL) == "" {
		return ValidationError{Field: "URL", Message: "URL is required when target method is URL"}
	}
	if m.SelectedReportType == "" {
		return ValidationError{Field: "SelectedReportType", Message: "report type is required"}
	}
	return nil
}
