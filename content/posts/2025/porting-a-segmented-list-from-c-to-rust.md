---
title: "Porting a Segmented List From C to Rust"
summary: "Macros, Token pasting and Custom allocators vs Traits, `Option<Box<[MaybeUninit<T>]>>` and the borrow checker"
date: 2025-09-28
tags:
  - rust
  - c
draft: true
---

I needed to replace my _growing list_ of three different dynamic array
implementations in my bytecode interpreter: one for Nodes, one for runtime
Values and one for bytecode. Building the AST and bytecode required a lot of
`malloc`, `realloc` and `memcpy`. I hacked a workaround together by introducing
a segmented bump allocator backed by `mmap` omitting the syscalls, but `memcpy`
still remained.

So I wrote (and debugged) a generic segmented list in C unifying those
implementations into the following features:

1. zero realloc
2. zero copy
3. lazy allocation on grow
4. backed by a bump allocator

I now want to port this to Rust and compare semantics, implementation,
performance and how pretty they look.

> This isn't a ***"C sucks because it's unsafe and Rust is super duper great
> because it borrow checks and it's safe"*** article, but rather a ***"I love C
> but lately I want to use Rust to help me get out of the pain of debugging my
> lexer, parser and compiler interacting with my segmented bump allocator
> backed by mmap, my handrolled generic segmented list and everything around
> that"***.

## Why Segmented Lists

Vectors suck at growing a lot, because:

1. They have to allocate a new and larger block
2. They have to copy their contents to the new space
3. They require to "update" all references into the previous space to the new
   space

### Design

### Indexing

## C Implementation

### Bump allocator

## Rust Implementation

### Bump allocator

## Runtime and Memory Comparison of C, Rust and std::vec::Vec

## Pain points
