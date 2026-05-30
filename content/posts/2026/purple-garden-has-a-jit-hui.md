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
| jitprogress_compile         |    8.0596 µs |     8.0742 µs |    8.0919 µs |
| jitprogress_compile_opt     |    8.6249 µs |     8.6334 µs |    8.6429 µs |
| jitprogress_compile_opt_jit |    17.136 µs |     17.176 µs |    17.224 µs |
| jitprogress_run             |    42.992 ns |     43.049 ns |    43.110 ns |
| jitprogress_run_opt         |    39.499 ns |     39.550 ns |    39.600 ns |
| jitprogress_run_opt_jit     |    11.211 ns |     11.265 ns |    11.320 ns |
| collatz_compile             |    14.508 µs |     14.519 µs |    14.534 µs |
| collatz_compile_opt         |    16.245 µs |     16.270 µs |    16.302 µs |
| collatz_compile_opt_jit     |    24.316 µs |     24.338 µs |    24.372 µs |
| collatz_run                 |    3.8873 ms |     3.8995 ms |    3.9135 ms |
| collatz_run_opt             |    2.2917 ms |     2.2940 ms |    2.2965 ms |
| collatz_run_opt_jit         |    1.9724 ms |     1.9744 ms |    1.9765 ms |

# The whole Pipeline

For the current progress / subset of supported immediate representation in the
sense that the jit can lower an IR node to x86 machine code. First the purple-garden source code:

```garden
fn arithmetics(a:int b:int c:int d:int) int {
    let x1 = a + b * c - d
    let x2 = x1 + c * d - b
    let x3 = x2 + x1 * a - c
    let x4 = x3 + x2 * b - d
    x4
}
arithmetics(2 3 4 5)
```

The the IR:

```llvm
// arithmetics
fn f1(%v0, %v1, %v2, %v3) -> Int {
b0(%v0, %v1, %v2, %v3):
        %v4:Int = IMul %v1, %v2
        %v5:Int = IAdd %v0, %v4
        %v6:Int = ISub %v5, %v3
        %v7:Int = IMul %v2, %v3
        %v8:Int = IAdd %v6, %v7
        %v9:Int = ISub %v8, %v1
        %v10:Int = IMul %v6, %v0
        %v11:Int = IAdd %v9, %v10
        %v12:Int = ISub %v11, %v2
        %v13:Int = IMul %v9, %v1
        %v14:Int = IAdd %v12, %v13
        %v15:Int = ISub %v14, %v3
        ret %v15
}

// entry
fn f0() -> void {
b0():
        %v0:Int = 2
        %v1:Int = 3
        %v2:Int = 4
        %v3:Int = 5
        %v4:Int = Call f1(%v0, %v1, %v2, %v3)
}
```

And the pg bytecode the interpreter is already able to
execute:

```asm
; when ran with --no-jit
00000000 <arithmetics>:
  0000:    push2 r4, r5            ; 1: fn arithmetics(a:int b:int c:int d:int) int {
  0001:    imul r4, r1, r2         ; 2: let x1 = a + b * c - d
  0002:    iadd r4, r0, r4
  0003:    isub r4, r4, r3
  0004:    imul r5, r2, r3         ; 3: let x2 = x1 + c * d - b
  0005:    iadd r5, r4, r5
  0006:    isub r5, r5, r1
  0007:    imul r0, r4, r0         ; 4: let x3 = x2 + x1 * a - c
  0008:    iadd r0, r5, r0
  0009:    isub r0, r0, r2
  000a:    imul r1, r5, r1         ; 5: let x4 = x3 + x2 * b - d
  000b:    iadd r0, r0, r1
  000c:    isub r0, r0, r3
  000d:    pop2 r5, r4
  000e:    ret

0000000f <entry>:
  000f:    load_imm r0, #2         ; 8: arithmetics(2 3 4 5)
  0010:    load_imm r1, #3
  0011:    load_imm r2, #4
  0012:    load_imm r3, #5
  0013:    call 0000 <arithmetics>
```

And finally the x86 version of `arithmetics`:

```asm
00000000 <entry>:
  0000:    load_imm r0, #2         ; 8: arithmetics(2 3 4 5)
  0001:    load_imm r1, #3
  0002:    load_imm r2, #4
  0003:    load_imm r3, #5
  0004:    sys 0 <jit_arithmetics>

<jit_arithmetics>:
  0000:    48 8b 47 00             ; mov rax, [rdi+0x0]
  0004:    48 8b 4f 08             ; mov rcx, [rdi+0x8]
  0008:    48 8b 57 10             ; mov rdx, [rdi+0x10]
  000c:    48 8b 77 18             ; mov rsi, [rdi+0x18]
  0010:    49 89 c8                ; mov r8, rcx
  0013:    4c 0f af c2             ; imul r8, rdx
  0017:    49 01 c0                ; add r8, rax
  001a:    49 29 f0                ; sub r8, rsi
  001d:    49 89 d1                ; mov r9, rdx
  0020:    4c 0f af ce             ; imul r9, rsi
  0024:    4d 01 c1                ; add r9, r8
  0027:    49 29 c9                ; sub r9, rcx
  002a:    4c 0f af c0             ; imul r8, rax
  002e:    4d 01 c8                ; add r8, r9
  0031:    49 29 d0                ; sub r8, rdx
  0034:    4c 0f af c9             ; imul r9, rcx
  0038:    4d 01 c1                ; add r9, r8
  003b:    49 29 f1                ; sub r9, rsi
  003e:    4c 89 4f 00             ; mov [rdi+0x0], r9
  0042:    c3                      ; ret
```

# Implementing a JIT

## x86 machine abstraction

## Mmaping RWX

## Basic register allocation

## Emitting x86

## Hooking the JIT up to the compiler

## How pg handles ffi or reusing the SYS op

## Profit
