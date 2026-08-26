package agentcfg

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/packagebeagle/beagle/internal/fsread"
	"github.com/packagebeagle/beagle/internal/model"
)

// IsTasksFile reports whether path is a VS Code tasks file.
func IsTasksFile(path string) bool {
	return filepath.Base(path) == "tasks.json" && filepath.Base(filepath.Dir(path)) == ".vscode"
}

type vsTask struct {
	Label      string   `json:"label"`
	Type       string   `json:"type"`
	Script     string   `json:"script"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	RunOptions struct {
		RunOn string `json:"runOn"`
	} `json:"runOptions"`
	Presentation *struct {
		Reveal *string `json:"reveal"`
		Echo   *bool   `json:"echo"`
		Focus  *bool   `json:"focus"`
		Close  *bool   `json:"close"`
	} `json:"presentation"`
}

// ScanTasks emits one record per task configured to run on folder open.
// Tasks with any other runOn (or none) are not auto-execution paths and
// produce no row.
func (s *Scanner) ScanTasks(path string, base model.Record) error {
	data, err := fsread.Bounded(path, s.MaxFileSize, s.Diag)
	if err != nil {
		return err
	}
	var doc struct {
		Tasks []vsTask `json:"tasks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		s.diag("warn", path, "parse tasks.json: "+err.Error())
		return nil
	}
	scope, projectPath := scopeForPath(path)
	for _, t := range doc.Tasks {
		if t.RunOptions.RunOn != "folderOpen" {
			continue
		}
		command := taskCommand(t)
		var sig Signals
		sig.ScanContent(command)
		sig.Set("command", RedactCommand(command))
		sig.Set("trigger", "folderOpen")
		sig.Set("presentation_suppressed", presentationSuppressed(t))
		s.emit(base, taskName(t), ConfigTypeTaskAutorun, AgentVSCode, scope, projectPath, path, sig)
	}
	return nil
}

func taskName(t vsTask) string {
	switch {
	case t.Label != "":
		return t.Label
	case t.Script != "":
		return t.Script
	default:
		return t.Command
	}
}

func taskCommand(t vsTask) string {
	if t.Command == "" {
		return t.Script
	}
	if len(t.Args) == 0 {
		return t.Command
	}
	return t.Command + " " + strings.Join(t.Args, " ")
}

// presentationSuppressed reports whether the task is configured to run
// without showing itself. In-the-wild folderOpen payloads set the full
// set so nothing appears on screen; any one of them is enough to flag.
func presentationSuppressed(t vsTask) bool {
	p := t.Presentation
	if p == nil {
		return false
	}
	switch {
	case p.Reveal != nil && *p.Reveal == "silent":
		return true
	case p.Echo != nil && !*p.Echo:
		return true
	case p.Focus != nil && !*p.Focus:
		return true
	case p.Close != nil && *p.Close:
		return true
	}
	return false
}
