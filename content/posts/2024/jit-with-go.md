---
title: "POC JIT With Go (plugins)"
summary: "Proof of concept for compiling arithmetic expressions on the fly"
date: 2024-01-05
tags:
  - go
---

I recently implemented a very rudimentary JIT compiler in go. This compiler
generates go source code, compiles it by invoking the go compiler and loading
the resulting shared object into the current process and invoking the compiled
function.

The scope is currently limited to arithmetic expressions. I implemented a
tree-walk interpreter as well as a byte code compiler and virtual machine to
compare this JIT to. The front-end (lexer, parser) is shared, the back-end is
specific to the approach of evaluation.

As mentioned before the scope I choose for this compiler is limited to
arithmetic expressions, thus I want to accept the following:

```text
1+1.2-5
```

## Tokenizing

We convert our character stream to tokens:

```text
NUMBER 1
PLUS
NUMBER 1.2
MINUS
NUMBER 5
```

## Parsing

We parse the tokens and produce an abstract syntax tree via recursive descent:

```text
Binary {
    Type: MINUS,
    Left: Binary {
        Type: PLUS,
        Left: Number {
            Value: 1
        }
        Right: Number {
            Value: 1.2
        }
    }
    Right: Number {
       Value: 5
    }
}
```

## Code-generation

I want to generate go code from the abstract syntax tree, I know for
arithmetics its pretty idiotic, but i want to evaluate the pipeline in a
comparable way to byte code compilation+evaluation and tree-walk interpreting.
Thus we generate the following go source code:

```go
package main
func Main()float64{return 1E+00+1.2E+00-5E+00}
```

{{<callout type="Tip">}}
The generated function has to be exported, otherwise the `plugin` package will
not recognize it. I had to choose this weird way of representing floating point
integers, because otherwise there would be some weird results caused by go not
casting numbers to floating point integers.
{{</callout>}}

## Compilation

The go compiler sits in an
[internal](https://pkg.go.dev/cmd/go#hdr-Internal_Directories) go package, see
its repo
[here](https://github.com/golang/go/tree/master/src/cmd/compile/internal) and I
could not include it in my JIT, thus I had to use
[`os/exec`](https://pkg.go.dev/os/exec) for invoking the compiler:

```go
package main

import (
    "os"
    "os/exec"
    "fmt"
)

func JIT() (func() float64, error) {
    generatedCode := `package main
func Main() float64 {
    return 1E+00+1.2E+00-5E+00
}
   `
    err := os.WriteFile("jit_output.go", []byte(generatedCode), 0777)
    if err != nil {
        return nil, err
    }
    cmd := exec.Command("go", "build", "-buildmode=plugin", "-o", "jit_output.so", "jit_output.go")
    err := cmd.Run()
    if err != nil {
        return nil, err
    }



    return nil, nil
}

func main() {
    function, err := JIT()
    if err != nil {
        panic(err)
    }
    fmt.Println(function())
}
```

This first step calls the compiler and wants it to build a go plugin.

{{<callout type="Tip">}}
See `go help build`:

```text
[...]

	-buildmode mode
		build mode to use. See 'go help buildmode' for more.

[...]
```

And `go help buildmode`:

```text
The 'go build' and 'go install' commands take a -buildmode argument which
indicates which kind of object file is to be built. Currently supported values
are:

[...]

	-buildmode=plugin
		Build the listed main packages, plus all packages that they
		import, into a Go plugin. Packages not named main are ignored.
[...]
```

{{</callout>}}

Now a go plugin called `jit_output.so` sits in our project root.

## Go plugins

Go features a package called [plugin](https://pkg.go.dev/plugin) for loading
and resolving go symbols of go plugins. There are some drawbacks such as
missing portability due to no windows support and easily exploitable bugs in
plugin loaders - since this is a POC JIT requiring the go compiler toolchain in
the path I'm not even going to walk down the road of portability.

Since we know the location of the plugin and the symbols in it our interactions
with the plugin packages should be minimal - I need to open the plugin file,
locate the `Main` function, cast it to `func() float64` and return the result.

```go {hl_lines=["27-43"]}
package main

import (
    "os"
    "os/exec"
    "fmt"
    "plugin"
    "errors"
)

func JIT() (func() float64, error) {
    generatedCode := `package main
func Main() float64 {
    return 1E+00+1.2E+00-5E+00
}
   `
    err := os.WriteFile("jit_output.go", []byte(generatedCode), 0777)
    if err != nil {
        return nil, err
    }
    cmd := exec.Command("go", "build", "-buildmode=plugin", "-o", "jit_output.so", "jit_output.go")
    err := cmd.Run()
    if err != nil {
        return nil, err
    }

    plug, err := plugin.Open("jit_output.so")
    if err != nil {
        return nil, err
    }

	symbol, err := plug.Lookup("Main")
	if err != nil {
		fmt.Println(sharedObjectPath)
		return nil, err
	}

	Main, ok := symbol.(func() float64)
	if !ok {
		return nil, errors.New("Error while accessing jit compiled symbols")
	}

	return Main, nil
}

func main() {
    function, err := JIT()
    if err != nil {
        panic(err)
    }
    fmt.Println(function())
}
```

## What to do with this JIT

My plan is to compare the three different approaches to evaluation techniques
in a blog article in the next few weeks, expect some in depth benchmarks.
