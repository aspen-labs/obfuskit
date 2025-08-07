package util

import (
	"fmt"
	"strings"
	"time"
)

// ProgressBar represents a simple progress bar
type ProgressBar struct {
	total     int
	current   int
	width     int
	prefix    string
	startTime time.Time
	enabled   bool
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, prefix string, enabled bool) *ProgressBar {
	return &ProgressBar{
		total:     total,
		current:   0,
		width:     50,
		prefix:    prefix,
		startTime: time.Now(),
		enabled:   enabled,
	}
}

// Update updates the progress bar
func (pb *ProgressBar) Update(current int) {
	if !pb.enabled {
		return
	}

	pb.current = current
	pb.render()
}

// Increment increments the progress bar by 1
func (pb *ProgressBar) Increment() {
	if !pb.enabled {
		return
	}

	pb.current++
	pb.render()
}

// Finish completes the progress bar
func (pb *ProgressBar) Finish() {
	if !pb.enabled {
		return
	}

	pb.current = pb.total
	pb.render()
	fmt.Println() // New line after completion
}

// render draws the progress bar
func (pb *ProgressBar) render() {
	if pb.total <= 0 {
		return
	}

	percentage := float64(pb.current) / float64(pb.total) * 100
	filled := int(float64(pb.width) * float64(pb.current) / float64(pb.total))

	bar := strings.Repeat("=", filled)
	if filled < pb.width {
		bar += ">"
		bar += strings.Repeat(" ", pb.width-filled-1)
	}

	elapsed := time.Since(pb.startTime)

	var eta string
	if pb.current > 0 {
		rate := float64(pb.current) / elapsed.Seconds()
		remaining := float64(pb.total-pb.current) / rate
		eta = fmt.Sprintf(" ETA: %s", time.Duration(remaining*float64(time.Second)).Round(time.Second))
	}

	fmt.Printf("\r%s [%s] %.1f%% (%d/%d)%s",
		pb.prefix, bar, percentage, pb.current, pb.total, eta)
}

// TaskProgress represents progress for a specific task
type TaskProgress struct {
	taskName string
	bar      *ProgressBar
}

// NewTaskProgress creates a new task progress tracker
func NewTaskProgress(taskName string, total int, enabled bool) *TaskProgress {
	return &TaskProgress{
		taskName: taskName,
		bar:      NewProgressBar(total, taskName, enabled),
	}
}

// Update updates the task progress
func (tp *TaskProgress) Update(current int) {
	tp.bar.Update(current)
}

// Increment increments the task progress
func (tp *TaskProgress) Increment() {
	tp.bar.Increment()
}

// Finish completes the task progress
func (tp *TaskProgress) Finish() {
	tp.bar.Finish()
	if tp.bar.enabled {
		fmt.Printf("✅ %s completed!\n", tp.taskName)
	}
}

// MultiTaskProgress manages multiple progress bars
type MultiTaskProgress struct {
	tasks   []*TaskProgress
	enabled bool
}

// NewMultiTaskProgress creates a new multi-task progress manager
func NewMultiTaskProgress(enabled bool) *MultiTaskProgress {
	return &MultiTaskProgress{
		tasks:   []*TaskProgress{},
		enabled: enabled,
	}
}

// AddTask adds a new task to track
func (mtp *MultiTaskProgress) AddTask(taskName string, total int) *TaskProgress {
	task := NewTaskProgress(taskName, total, mtp.enabled)
	mtp.tasks = append(mtp.tasks, task)
	return task
}

// Finish completes all tasks
func (mtp *MultiTaskProgress) Finish() {
	for _, task := range mtp.tasks {
		task.Finish()
	}
}
