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
		item{"All", "Generate payloads for all attacks"},
		item{"XSS", "Cross Site Scripting"},
		item{"SQLi", "SQL Injection"},
		item{"LFI", "Local File Inclusion"},
		item{"RFI", "Remote File Inclusion"},
		item{"Command Injection", "OS Command Injection"},
		item{"SSRF", "Server-Side Request Forgery"},
		item{"XXE", "XML External Entity"},
	}

	evasionItems = []list.Item{
		item{"All", "Generate payloads with all possible evasions"},
		item{"Encodings", "Generate payloads with all possible encodings"},
		item{"Paths", "Generate payloads with all possible paths"},
		item{"Commands", "Generate payloads with all possible commands"},
	}

	reports = []list.Item{
		item{"HTML", "Generate HTML Report"},
		item{"PDF", "Generate PDF Report"},
		item{"Terminal", "Generate Terminal Report"},
	}
)

type state int

const (
	stateMainMenu state = iota
	stateChooseAttack
	stateChooseEvasion
	stateChooseReport
	stateDone
)

type model struct {
	list            list.Model
	current         state
	selection       string
	selectedAttack  string
	selectedEvasion string
	selectedReport  string
	ready           bool
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
				m.selection = selected
				if selected == "Generate Payloads" {
					m.list.SetItems(attackItems)
					m.list.Title = "Choose attack type:"
					m.current = stateChooseAttack
				} else {
					m.current = stateDone
					return m, tea.Quit
				}
			case stateChooseAttack:
				m.selectedAttack = m.list.SelectedItem().(item).title
				m.list.SetItems(evasionItems)
				m.list.Title = "Choose evasion method:"
				m.current = stateChooseEvasion
			case stateChooseEvasion:
				m.selectedEvasion = m.list.SelectedItem().(item).title
				m.list.SetItems(reports)
				m.list.Title = "Choose report format:"
				m.current = stateChooseReport
			case stateChooseReport:
				m.selectedReport = m.list.SelectedItem().(item).title
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
	case stateMainMenu, stateChooseAttack, stateChooseEvasion, stateChooseReport:
		return m.list.View()
	case stateDone:
		summary := fmt.Sprintf(`
  Main Action  : %s, Attack Type  : %s, Evasion Type : %s, Report Type  : %s`, m.selection, m.selectedAttack, m.selectedEvasion, m.selectedReport)
		return summary
	default:
		return "Something went wrong."
	}
}

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
		fmt.Println("\n🚀 Ready to use selections:")
		fmt.Printf("Main: %s\nAttack: %s\nEvasion: %s\nReport: %s\n",
			m.selection, m.selectedAttack, m.selectedEvasion, m.selectedReport)

		// Insert logic here to use these selections
		// e.g. generatePayloads(m.attackType, m.evasionType)
	},
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}
