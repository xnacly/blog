---
title: "Engineering the Stdlib for Purple Garden"
summary: "Extending the purple-garden AST,IR,codegen and VM to support its standard library"
date: 2026-06-08
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


# Setup, Documentation and Discoverability

## Registering Packages and Functions

```rust
```

## The 'doc' sub command

```text
```

# Extending the Tokenizer

```rust
```

```rust
```

# Parsing and adding Import and Usage Nodes

```rust
```

```rust
```

# Registering packages and method calls in the typechecker

```rust
```

## Resolving packages

```rust
```

## Typechecking package calls

```rust
```

# A new IR Instruction Variant for std Method Calls

```rust
```

## Lowering Node::Import

```rust
```

```rust
```

## Lowering the call

```rust
```

# 'Op::Sys' and Lowering to Bytecode

```rust
```

```rust
```

# Std interactions in the virtual machine

```rust
```

```rust
```

# Introspection in the bytecode disassembly

```asm
```

```rust
```
