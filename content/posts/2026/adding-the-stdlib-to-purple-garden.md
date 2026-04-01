---
title: "Engineering the Stdlib for Purple Garden"
summary: "Extending the purple-garden AST,IR,codegen and VM to support its standard library"
date: 2026-03-31
draft: true
tags:
  - rust
  - pldev
---

# Designing the stdlib 

## Scope

## Importing Packages

## Using Packages and Calling Methods

# Constraints

- Performance
- Readability
- Usability
- Trade-off between Fat and Slim standard libraries

# Inspirations

- go

# Setup, Documentation and Discoverability

## Registering Packages and Functions

## Type-safety throughout the pipeline

## The 'doc' sub command

```text
$ purple-garden doc
Purple garden standard library packages:
io
strings
conv
test
$ purple-garden doc io
import (io)

Package io provides rudimentary I/O primitives,
like writing and reading from file descriptors

fn println(Str) Void
fn print(Str) Void

$ purple-garden doc io.println
fn println(Str) Void
        writes its argument to stdout, with a newline appended
```

# Extending the Tokenizer

# Parsing and adding Import and Usage Nodes

# Registering packages and method calls in the typechecker

# A new IR Instruction Variant for std Method Calls

# 'Op::Sys' and Lowering to Bytecode

# Std interactions in the virtual machine

# Introspection in the bytecode disassembly

# Benchmarks?
