---
title: "Building The Worst Vi Emulation for My Mail Client"
summary: "Naive vi like motion subset emulation bolted on top of bubbletea in 120loc"
date: 2026-02-18T00:02:23+01:00
tags:
- Go
- Vim
---

# Why, What and How exactly


I wasnt able to grasp mutt in 25 **seconds** and decided I have to write my own
alternative terminal mail client, its name is:
[postbote](https://github.com/xnacly/postbote). 

A screenshot:

![postbote screenshot main page](/postbote/postbote.png)


It does way less, is a work in progress but its mine and therefore I need vi
style motions. I also need:

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

> I'm aware this isn't fully what vi motions do, simply because they are way
> more powerful. The goal is to implement a subset of this composability so I
> have my muscle memory while looking at and writing my emails.

I define a motion as a combination of a modifier and a command. Since I wont
add visual selections or other ranges I decided to go with the modifier being a
number. And the command being a string. For instance typing `12gf` will open
the file with the id 12.

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

# Valid Commands, Prefixes and Chars

Recognising an input as valid, requires a list of valid commands:

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

Only accepting chars included in the above list and only accepting a
combination thats a valid prefix requires me to keep three lookup tables filled
at compilation unit runtime init: 

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

> `validPrefixes` could be a [trie](https://en.wikipedia.org/wiki/Trie), but
> thusfar postbote only has 11 commands. Ill get to it, once it hits the fan
> and is too slow.

# Interacting with bubbletea

Since I use bubbletea with bubbles and lipgloss, I want to use the built in way
of dealing with inputs bubbletea provides. For this the `vi` emulation state is
attached to the bubbletea model.

```go
type model struct {
	vi        vi
    // [...]
}
```

Since the keyboard handling is in `Update` (satistfying `tea.Model` requires
implementing `Init`, `Update` and `View`) type switching on the `tea.Msg` gives
me the `tea.KeyMsg` holding the state for a key input.

We pass the msg to `vi.update` and if the vi state signals us there is a
complete motion recognised (`some`), we act on `msg.command`, for instance if
`q` was recognised:

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

# Vi'ing all over the place

So this is the heart of the whole thing. Its a small state machine working as
follows:

1. if `esc` reset state and exit
2. if not single rune exit (rune is a go `char`, see [Code points, characters, and runes](https://go.dev/blog/strings#code-points-characters-and-runes))
3. if numeric rune, update the `modifier`
4. if a valid alhabetic rune, write it to the `command` buffer
5. if the current string repr of the buffer (cmd) is a valid command, produce a
   `viMessage`, reset vi state and return the msg
6. if cmd is not a valid prefix for a command, reset vi state

This architecture makes it easy to add new commands and explicitily forbids
motions like `g2f`, since only `<modifier><command>` is valid.

```go
// represent a fully detected vi motion
type viMessage struct {
	modifier uint
	command  string
}

// convert the current vi state into a viMessage model.Update can deal with
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


Reset is as simple as it gets.

```go
func (v *vi) reset() {
	v.modifier = 0
	v.command.Reset()
}
```

# Pending, Sprinting and Render(ing)

```go
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

The `pending` is used to display the current pending motion at the right side
of the status bar, similar to vim's display:

```go
func (m model) status(width int) string {
    left := // [...] left side of the status bar

	viPending := m.vi.pending()

	left = lipgloss.NewStyle().
		Width(width - lipgloss.Width(viPending) - 4).
		Align(lipgloss.Left).
		Render(left)

	return left + viPending
}
```

In the `View` function status is called:

```go
func (m model) View() string {
	layout := lipgloss.JoinHorizontal(lipgloss.Top,
        // [...] the three panes 
        // | parent dir | current dir | preview | 
	)

	status := statusStyle.Render(m.status(m.width))
    // joining produces:
    // 
    // | parent dir | current dir | preview | 
    // path fcount mcount              motion
	return lipgloss.JoinVertical(lipgloss.Left, layout, status)
}
```

# Adding a new command

```diff
diff --git a/ui/vi.go b/ui/vi.go
index 63cfa24..5087c6a 100644
--- a/ui/vi.go
+++ b/ui/vi.go
@@ -36,6 +36,7 @@ var validCommandList = []string{
        "q",
        "/",
        "a",
+       "i",
 }
 var validCommands = map[string]struct{}{}
 var validRunes = map[rune]struct{}{}
```

Is all thats necessary for introducing a new binding, handling it works the
same as shown before:

```diff
diff --git a/ui/tea.go b/ui/tea.go
index 20d211a..a3123e7 100644
--- a/ui/tea.go
+++ b/ui/tea.go
@@ -77,6 +77,10 @@ func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
  case tea.KeyMsg:
      if msg, some := m.vi.update(typed); some {
          switch msg.command {
+         case "i":
+                 // i is used to Insert text into the current mail and maybe
+                 // respond to it inline or something
+                 return m, nil
          case "q":
                  return m, tea.Quit
          }
```
