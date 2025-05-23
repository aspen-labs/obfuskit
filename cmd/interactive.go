package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

type item struct {
	title, desc string
}

func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.desc }
func (i item) FilterValue() string { return i.title }

var (
	mainMenuItems = []list.Item{
		item{"Generate Payloads", "Generate and view possible attack payloads"},
		item{"Send to URL", "Generate payloads and send them to a test URL"},
		item{"Use Existing Payloads", "Give a path or enter a list of payloads"},
	}

	attackItems = []list.Item{
		item{"I'll pick", "Choose a specific attack type"},
		item{"All", "Use all available attack types"},
	}

	specificAttackItems = []list.Item{
		item{"XSS", "Cross Site Scripting"},
		item{"SQLi", "SQL Injection"},
		item{"LFI", "Local File Inclusion"},
		item{"RFI", "Remote File Inclusion"},
		item{"Command Injection", "OS Command Injection"},
		item{"SSRF", "Server-Side Request Forgery"},
		item{"XXE", "XML External Entity"},
	}

	payloadItems = []list.Item{
		item{"I'll pick", "Choose a specific payload evasion method"},
		item{"All", "Use all available payload evasion methods"},
	}

	specificPayloadItems = []list.Item{
		item{"Encodings", "Generate payloads with various encodings"},
		item{"Paths", "Generate payloads with various path structures"},
		item{"Commands", "Generate payloads with various command structures"},
	}

	targetItems = []list.Item{
		item{"Specify URL", "Enter a specific target URL"},
		item{"Save to file", "Save payloads to a file instead of targeting a URL"},
	}

	reportItems = []list.Item{
		item{"I'll pick", "Choose a specific report format"},
		item{"All", "Generate reports in all available formats"},
	}

	specificReportItems = []list.Item{
		item{"HTML", "Generate a formatted HTML Report"},
		item{"Pretty Terminal", "Generate a formatted report in the terminal"},
		item{"PDF", "Generate a PDF document report"},
		item{"CSV", "Generate data in CSV format"},
	}
)

type state int

const (
	stateMainMenu state = iota
	stateChooseAttackMethod
	stateChooseSpecificAttack
	stateChoosePayloadMethod
	stateChooseSpecificPayload
	stateChooseTarget
	stateEnterURL
	stateChooseReportMethod
	stateChooseSpecificReport
	stateDone
)

type model struct {
	list               list.Model
	current            state
	Selection          string
	SelectedAttack     string
	SelectedPayload    string
	SelectedTarget     string
	SelectedReportType string
	Url                string
	ready              bool
	autoAttack         bool
	autoPayload        bool
	autoReport         bool
}

func initialModel() model {
	l := list.New(mainMenuItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Select what you want to do:"
	return model{list: l, current: stateMainMenu}
}

func (m model) Init() tea.Cmd {
	return tea.EnterAltScreen
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if !m.ready {
			m.list.SetSize(msg.Width, msg.Height-2)
			m.ready = true
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			switch m.current {
			case stateMainMenu:
				selected := m.list.SelectedItem().(item).title
				m.Selection = selected
				m.list.SetItems(attackItems)
				m.list.Title = "Choose attack type:"
				m.current = stateChooseAttackMethod

			case stateChooseAttackMethod:
				if m.list.SelectedItem().(item).title == "I'll pick" {
					m.autoAttack = false
					m.list.SetItems(specificAttackItems)
					m.list.Title = "Choose specific attack type:"
					m.current = stateChooseSpecificAttack
				} else {
					m.autoAttack = true
					m.SelectedAttack = "All"
					// Go to payload method selection
					m.list.SetItems(payloadItems)
					m.list.Title = "Choose payload method:"
					m.current = stateChoosePayloadMethod
				}

			case stateChooseSpecificAttack:
				m.SelectedAttack = m.list.SelectedItem().(item).title
				// Go to payload method selection
				m.list.SetItems(payloadItems)
				m.list.Title = "Choose payload method:"
				m.current = stateChoosePayloadMethod

			case stateChoosePayloadMethod:
				if m.list.SelectedItem().(item).title == "I'll pick" {
					m.autoPayload = false
					m.list.SetItems(specificPayloadItems)
					m.list.Title = "Choose specific payload evasion method:"
					m.current = stateChooseSpecificPayload
				} else {
					m.autoPayload = true
					m.SelectedPayload = "All"
					m.list.SetItems(targetItems)
					m.list.Title = "Choose target method:"
					m.current = stateChooseTarget
				}

			case stateChooseSpecificPayload:
				m.SelectedPayload = m.list.SelectedItem().(item).title
				// Go to target selection
				m.list.SetItems(targetItems)
				m.list.Title = "Choose target method:"
				m.current = stateChooseTarget

			case stateChooseTarget:
				if m.list.SelectedItem().(item).title == "Specify URL" {
					m.SelectedTarget = "URL"
					m.list.Title = "Enter URL (placeholder - would be input field):"
					m.current = stateEnterURL
					// In a real implementation, you would handle URL input here
					// This is just a placeholder for the UI flow
					m.Url = "https://example.com" // Placeholder
				} else {
					m.SelectedTarget = "File"
					m.Url = "output.txt" // Placeholder filename
					// Go to report method selection
					m.list.SetItems(reportItems)
					m.list.Title = "Choose report format:"
					m.current = stateChooseReportMethod
				}

			case stateEnterURL:
				// In a real implementation, this would capture the URL input
				// For now, just proceed to report selection
				m.list.SetItems(reportItems)
				m.list.Title = "Choose report format:"
				m.current = stateChooseReportMethod

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
				m.SelectedReportType = m.list.SelectedItem().(item).title
				m.current = stateDone
				return m, tea.Quit
			}
		case "q":
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) View() string {
	switch m.current {
	case stateMainMenu, stateChooseAttackMethod, stateChooseSpecificAttack, stateChoosePayloadMethod,
		stateChooseSpecificPayload, stateChooseTarget, stateEnterURL, stateChooseReportMethod, stateChooseSpecificReport:
		return m.list.View()
	case stateDone:
		summary := fmt.Sprintf(`
  Main Action    : %s
  Attack Type    : %s %s
  Evasion Method : %s %s
  Target         : %s (%s)
  Report Type    : %s %s`,
			m.Selection,
			m.SelectedAttack, autoString(m.autoAttack),
			m.SelectedPayload, autoString(m.autoPayload),
			m.SelectedTarget, m.Url,
			m.SelectedReportType, autoString(m.autoReport))
		return summary
	default:
		return "Something went wrong."
	}
}

func autoString(auto bool) string {
	if auto {
		return "(all selected)"
	}
	return ""
}

var FinalSelection model

var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Interactive terminal UI for selecting payload generation options",
	Run: func(cmd *cobra.Command, args []string) {
		p := tea.NewProgram(initialModel())
		finalModel, err := p.StartReturningModel()
		if err != nil {
			fmt.Println("Error running interactive UI:", err)
			os.Exit(1)
		}

		m := finalModel.(model)
		FinalSelection = m
		fmt.Println("\nConfiguration Summary:")
		fmt.Printf("Main Action    : %s\n", m.Selection)
		fmt.Printf("Attack Type    : %s %s\n", m.SelectedAttack, autoString(m.autoAttack))
		fmt.Printf("Evasion Method : %s %s\n", m.SelectedPayload, autoString(m.autoPayload))
		fmt.Printf("Target         : %s (%s)\n", m.SelectedTarget, m.Url)
		fmt.Printf("Report Type    : %s %s\n", m.SelectedReportType, autoString(m.autoReport))

		// Insert logic here to use these selections
		// For example:
		// if m.autoAttack {
		//     attackType = chooseOptimalAttack()
		// } else {
		//     attackType = m.selectedAttack
		// }
		// etc.
	},
}

func GetFinalSelection() model {
	Execute()
	return FinalSelection
}
func init() {
	rootCmd.AddCommand(interactiveCmd)
}
