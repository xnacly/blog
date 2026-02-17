---
title: "Building The Worst Vim Emulation for My Mail Client"
summary: "Naive vim motion subset emulation bolted on top of bubbletea in 120loc"
date: 2026-02-18T00:02:23+01:00
draft: true
tags:
- Go
- Vim
---

# Why, What and How exactly

![postbote screenshot main page](/postbote/postbote.png)

I wasnt able to grasp mutt in 25 seconds and decided I have to write my own
alternative terminal mail client, its name is:
[postbote](https://github.com/xnacly/postbote). It does way less, is a work in
progress but its mine and therefore I need vi style motions. I also need:


- a single, opinionated configuration
- a go template based scripting and commands system
- IMAP, SMTP support via ProtonMail Bridge or any standard server
- most MIME types supported by default
  - images are rendered to the terminal
  - text plain is simply rendered
  - html is converted to text
  - others configurable in postbote.toml:

  ```toml
  # execute commands when an attachment with a matching mime type 
  # is opened via <id>gf
  [MIME]
  "application/pdf" = "zathura --fork {{file.path}}"
  "text/plain"      = "nvim -R {{file.path}}"
  ```

# Motions (my definition)

```go
// Vi style motion emulation.
//
//	count command
//
// Where
//
//	count := \d*
//	command := [hjklgGqfx]+
//
// Enables behaviour like 25j for moving 25 mails down, 
// 2gf for going to the second attachment and gx for 
// opening an url or file path via the operating
// systems open behaviour
type vi struct {
	modifier uint
	command  strings.Builder
}
```

# Valid commands

```go
var validCommandList = []string{
	"h",
	"j",
	"k",
	"l",
	"G",
	"gg",
	"gf",
	"gx",
	"q",
	"/",
	"a",
}
```

# Prefixes and Chars in and of valid commands

```go
var validCommands = map[string]struct{}{}
var validRunes = map[rune]struct{}{}
var validPrefixes = map[string]struct{}{}

func init() {
	for _, cmd := range validCommandList {
		validCommands[cmd] = struct{}{}
		for _, r := range cmd {
			validRunes[r] = struct{}{}
		}
		// this is currently the best way i can think of,
        // besides a trie, which i dont think is 
        // necessary for a whole 11 commands
		for i := 1; i <= len(cmd); i++ {
			validPrefixes[cmd[:i]] = struct{}{}
		}
	}
}
```

# Interacting with bubbletea

```go
type model struct {
	vi        vi
    // [...]
}
```

```go
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := msg.(type) {
	case tea.WindowSizeMsg:
    // [...]
    case tea.KeyMsg:
		if msg, some := m.vi.update(typed); some {
			switch msg.command {
			case "q":
				return m, tea.Quit
			}
		}
	}

	return m, nil
}
```

# Reset

```go
func (v *vi) reset() {
	v.modifier = 0
	v.command.Reset()
}
```


# Pending and Render(ing)

```go
// represent a fully detected vi motion
type viMessage struct {
	modifier uint
	command  string
}

func (msg viMessage) String() string {
	if msg.modifier == 0 || msg.modifier == 1 {
		return fmt.Sprint(msg.command)
	} else {
		return fmt.Sprint(msg.modifier, msg.command)
	}
}

func (v *vi) pending() string {
	return v.toViMessage().String()
}
```

```go
func (m model) status(width int) string {
	left := fmt.Sprintf("%s (d:%d;m:%d)",
		m.current.Path,
		len(m.current.Folders),
		len(m.current.Messages),
	)

	viPending := m.vi.pending()

	left = lipgloss.NewStyle().
		Width(width - len(viPending) - 4).
		Align(lipgloss.Left).
		Render(left)

	return left + viPending
}
```

# All together :^)

```go
package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Vi style motion emulation.
//
//	count command
//
// Where
//
//	count := \d*
//	command := [hjklgGqfx]+
//
// Enables behaviour like 25j for moving 25 mails down, 
// 2gf for going to the second attachment and gx for 
// opening an url or file path via the operating
// systems open behaviour
type vi struct {
	modifier uint
	command  strings.Builder
}

var validCommandList = []string{
	"h",
	"j",
	"k",
	"l",
	"G",
	"gg",
	"gf",
	"gx",
	"q",
	"/",
	"a",
}
var validCommands = map[string]struct{}{}
var validRunes = map[rune]struct{}{}
var validPrefixes = map[string]struct{}{}

func init() {
	for _, cmd := range validCommandList {
		validCommands[cmd] = struct{}{}
		for _, r := range cmd {
			validRunes[r] = struct{}{}
		}
        // this is currently the best way i can think of,
        // besides a trie, which i dont think is 
        // necessary for a whole 11 commands
		for i := 1; i <= len(cmd); i++ {
			validPrefixes[cmd[:i]] = struct{}{}
		}
	}
}

// represent a fully detected vi motion
type viMessage struct {
	modifier uint
	command  string
}

func (msg viMessage) String() string {
	if msg.modifier == 0 || msg.modifier == 1 {
		return fmt.Sprint(msg.command)
	} else {
		return fmt.Sprint(msg.modifier, msg.command)
	}
}

func (v *vi) reset() {
	v.modifier = 0
	v.command.Reset()
}

func (v *vi) pending() string {
	return v.toViMessage().String()
}

// convert the current vi state into a 
// viMessage model.Update can deal with
func (v *vi) toViMessage() viMessage {
	msg := viMessage{
		modifier: v.modifier,
		command:  v.command.String(),
	}
	return msg
}

func (v *vi) update(msg tea.KeyMsg) (viMessage, bool) {
	switch msg.Type {
	case tea.KeyEsc:
		v.reset()
	case tea.KeyRunes:
		if len(msg.Runes) != 1 {
			return viMessage{}, false
		}
		k := msg.Runes[0]
		switch {
		case k >= '0' && k <= '9' && v.command.Len() == 0:
			v.modifier = v.modifier*10 + uint(k-'0')
		default:
			if _, ok := validRunes[k]; ok {
				v.command.WriteRune(k)
				cmd := v.command.String()
				if _, ok := validCommands[cmd]; ok {
					vimsg := v.toViMessage()
					v.reset()
					return vimsg, true
				}

				if _, ok := validPrefixes[cmd]; !ok {
					v.reset()
				}
			}
		}
	}

	return viMessage{}, false
}
```
