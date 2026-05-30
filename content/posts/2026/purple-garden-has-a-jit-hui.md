---
title: "Purple Garden Has a JIT now :O"
date: 2026-05-29
summary: "Babies (me) first JIT, how it works, how fast it is and why, also x86 (Booh!)"
draft: true
tags:
  - pldev
  - rust
---

Lets start with some measurements:

| Benchmark                   | Time (Lower) | Time (Median) | Time (Upper) |
| --------------------------- | -----------: | ------------: | -----------: |
| collatz_compile             |    14.508 µs |     14.519 µs |    14.534 µs |
| collatz_compile_opt         |    16.245 µs |     16.270 µs |    16.302 µs |
| collatz_compile_opt_jit     |    24.316 µs |     24.338 µs |    24.372 µs |
| collatz_run                 |    3.8873 ms |     3.8995 ms |    3.9135 ms |
| collatz_run_opt             |    2.2917 ms |     2.2940 ms |    2.2965 ms |
| collatz_run_opt_jit         |    1.9724 ms |     1.9744 ms |    1.9765 ms |

I also have `jitprogress_run_{opt, opt_jit}` and `jitprogress_compile_{opt,
opt_jit}` benchmarks to keep track of opt and jit compile cost and their impact
on performance.

# The whole Pipeline

For the current progress / subset of supported immediate representation in the
sense that the jit can lower an IR node to x86 machine code. First the purple-garden source code:

```garden
```

The the IR:

```llvm
```

And the pg bytecode the interpreter is already able to
execute:

```asm
; when ran with --no-jit
```

And finally the x86 version of `arithmetics`:

```asm
```

# Implementing a JIT

## x86 machine abstraction

## Mmaping RWX

## Basic register allocation

## Emitting x86

## Hooking the JIT up to the compiler

## How pg handles ffi or reusing the SYS op

## Profit
