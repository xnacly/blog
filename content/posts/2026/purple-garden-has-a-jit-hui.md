---
title: "Purple Garden Has a JIT now :O"
date: 2026-05-29
summary: "Babys (me) first JIT, how it works, how fast it is and why, also x86 (Booh!)"
draft: true
tags:
  - pldev
  - rust
---

Lets start with some measurements:

| Benchmark             | Tier     |      Time | Delta vs baseline |  Ratio |
| --------------------- | -------- | --------: | ----------------: | -----: |
| **collatz compile**   | baseline |   7.66 µs |                   |        |
|                       | +opt     |   9.45 µs |    +23.30% slower |  0.81x |
|                       | +opt+jit |  12.18 µs |    +59.01% slower |  0.63x |
| **collatz run**       | baseline | 2059.5 µs |                   |      — |
|                       | +opt     | 1277.0 µs |    -37.99% faster |  1.61x |
|                       | +opt+jit |  927.5 µs |    -54.97% faster |  2.22x |
| **factorial compile** | baseline |   5.30 µs |                   |        |
|                       | +opt     |   4.37 µs |    -17.46% faster |  1.21x |
|                       | +opt+jit |   7.05 µs |    +33.17% slower |  0.75x |
| **factorial run**     | baseline |  225.1 ns |                   |        |
|                       | +opt     |  125.2 ns |    -44.39% faster |  1.80x |
|                       | +opt+jit |   20.9 ns |    -90.73% faster | 10.79x |

I also have `jitprogress_run_{opt, opt_jit}` and `jitprogress_compile_{opt,
opt_jit}` benchmarks to keep track of opt and jit compile cost and their impact
on performance relative to their baselines.

# The whole Pipeline

For the current progress / subset of supported immediate representation in the
sense that the jit can lower an IR node to x86 machine code. First the
purple-garden source code:

```python
import "testing"

fn arithmetics(a:Int b:Int c:Int d:Int) Int {
    let x1 = a + b * c - d
    let x2 = x1 + c * d - b
    let x3 = x2 + x1 * a - c
    let x4 = x3 + x2 * b - d
    x4 + x1 % 2
}

fn divs(a:Int b:Int) Int {
    a / 7 + b % 3
}

fn absish(n:Int) Int {
    match {
        n == 0 { 1 }
        { 2 }
    }
}

fn factorial(n:Int a:Int) Int {
    match {
        n == 0 { a }
        { factorial(n - 1 n * a) }
    }
}

testing.assert(arithmetics(2 3 4 5) == 114)
testing.assert(divs(42 17) == 8)
testing.assert(absish(0) == 1)
testing.assert(absish(5) == 2)
testing.assert(factorial(20 1) == 2432902008176640000)
```

Then the corresponding IR (omitting the entry point with all the assertions):

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
        %v17:Int = IMod %v6, 2
        %v18:Int = IAdd %v15, %v17
        ret %v18
}

// divs
fn f2(%v0, %v1) -> Int {
b0(%v0, %v1):
        %v3:Int = IDiv %v0, 7
        %v5:Int = IMod %v1, 3
        %v6:Int = IAdd %v3, %v5
        ret %v6
}

// absish
fn f3(%v0) -> Int {
b0(%v0):
b1(%v0):
        br_imm IEq %v0, 0, b2(%v0), b3(%v0)
b2(%v0):
        %v3:Int = 1
        ret %v3
b3(%v0):
        %v4:Int = 2
        ret %v4
b4(%v4):
        <tombstone>
}

// factorial
fn f4(%v0, %v1) -> Int {
b0(%v0, %v1):
b1(%v0, %v1):
        br_imm IEq %v0, 0, b4(%v1), b3(%v0, %v1)
b2(%v0, %v1):
        <tombstone>
b3(%v0, %v1):
        %v5:Int = ISub %v0, 1
        %v6:Int = IMul %v0, %v1
        tail f4(%v5, %v6)
b4(%v7):
        ret %v7
}
```

And the pg bytecode the interpreter is already able to
execute:

```asm
; when ran with --no-jit:
;
; purple-garden -Dd --no-jit examples/jitprogress.garden
globals:
  0000:    2432902008176640000

00000000 <arithmetics>:
  0000:    push2 r4, r5                               ; 3: fn arithmetics(a:Int b:Int c:Int d:Int) Int {
  0001:    imul r4, r1, r2                            ; 4: let x1 = a + b * c - d
  0002:    iadd r4, r0, r4
  0003:    isub r4, r4, r3
  0004:    imul r5, r2, r3                            ; 5: let x2 = x1 + c * d - b
  0005:    iadd r5, r4, r5
  0006:    isub r5, r5, r1
  0007:    imul r0, r4, r0                            ; 6: let x3 = x2 + x1 * a - c
  0008:    iadd r0, r5, r0
  0009:    isub r0, r0, r2
  000a:    imul r1, r5, r1                            ; 7: let x4 = x3 + x2 * b - d
  000b:    iadd r0, r0, r1
  000c:    isub r0, r0, r3
  000d:    imod_imm r1, r4, #2                        ; 8: x4 + x1 % 2
  000e:    iadd r0, r0, r1
  000f:    pop2 r5, r4
  0010:    ret

00000011 <divs>:
  0011:    idiv_imm r0, r0, #7                        ; 11: a / 7 + b % 3
  0012:    imod_imm r1, r1, #3
  0013:    iadd r0, r0, r1
  0014:    ret                                        ; 10: fn divs(a:Int b:Int) Int {

00000015 <absish>:
  0015:    push r1                                    ; 14: fn absish(n:Int) Int {
  0016:    jmpne_imm r0, #0, 001b <absish.bb_001b>    ; 16: n == 0 { 1 }
  0017:    load_imm r1, #1
  0018:    mov r0, r1
  0019:    pop r1
  001a:    ret
0000001b <absish.bb_001b>:
  001b:    load_imm r0, #2                            ; 17: { 2 }
  001c:    pop r1
  001d:    ret

0000001e <factorial>:
  001e:    push2 r2, r3                               ; 21: fn factorial(n:Int a:Int) Int {
  001f:    mov r2, r1                                 ; 23: n == 0 { a }
  0020:    jmpeq_imm r0, #0, 0026 <factorial.bb_0026>
  0021:    isub_imm r3, r0, #1                        ; 24: { factorial(n - 1 n * a) }
  0022:    imul r1, r0, r1
  0023:    mov r0, r3
  0024:    pop2 r3, r2
  0025:    tail 001e <factorial>
00000026 <factorial.bb_0026>:
  0026:    mov r0, r2
  0027:    pop2 r3, r2
  0028:    ret
```

And finally the x86 version of `arithmetics` (yes `purple-garden -DD` dumps ELF
format to stdout):

```gas
; objdump -d (purple-garden -DDd examples/jitprogress.garden|psub)

Disassembly of section .text:

0000000000000000 <jit_arithmetics>:
   0:   48 8b 47 00             mov    0x0(%rdi),%rax
   4:   48 8b 4f 08             mov    0x8(%rdi),%rcx
   8:   48 8b 57 10             mov    0x10(%rdi),%rdx
   c:   48 8b 77 18             mov    0x18(%rdi),%rsi
  10:   49 89 c8                mov    %rcx,%r8
  13:   4c 0f af c2             imul   %rdx,%r8
  17:   49 01 c0                add    %rax,%r8
  1a:   49 29 f0                sub    %rsi,%r8
  1d:   49 89 d1                mov    %rdx,%r9
  20:   4c 0f af ce             imul   %rsi,%r9
  24:   4d 01 c1                add    %r8,%r9
  27:   49 29 c9                sub    %rcx,%r9
  2a:   49 0f af c0             imul   %r8,%rax
  2e:   4c 01 c8                add    %r9,%rax
  31:   48 29 d0                sub    %rdx,%rax
  34:   4c 0f af c9             imul   %rcx,%r9
  38:   49 01 c1                add    %rax,%r9
  3b:   49 29 f1                sub    %rsi,%r9
  3e:   49 81 e0 01 00 00 00    and    $0x1,%r8
  45:   4d 01 c8                add    %r9,%r8
  48:   4c 89 47 00             mov    %r8,0x0(%rdi)
  4c:   c3                      ret

000000000000004d <jit_divs>:
  4d:   48 8b 47 00             mov    0x0(%rdi),%rax
  51:   48 8b 77 08             mov    0x8(%rdi),%rsi
  55:   48 89 c0                mov    %rax,%rax
  58:   48 99                   cqto
  5a:   48 c7 c1 07 00 00 00    mov    $0x7,%rcx
  61:   48 f7 f9                idiv   %rcx
  64:   49 89 c0                mov    %rax,%r8
  67:   48 89 f0                mov    %rsi,%rax
  6a:   48 99                   cqto
  6c:   48 c7 c1 03 00 00 00    mov    $0x3,%rcx
  73:   48 f7 f9                idiv   %rcx
  76:   48 89 d6                mov    %rdx,%rsi
  79:   4c 01 c6                add    %r8,%rsi
  7c:   48 89 77 00             mov    %rsi,0x0(%rdi)
  80:   c3                      ret

0000000000000081 <jit_absish>:
  81:   48 8b 47 00             mov    0x0(%rdi),%rax
  85:   48 85 c0                test   %rax,%rax
  88:   0f 85 0c 00 00 00       jne    9a <jit_absish+0x19>
  8e:   48 c7 c1 01 00 00 00    mov    $0x1,%rcx
  95:   48 89 4f 00             mov    %rcx,0x0(%rdi)
  99:   c3                      ret
  9a:   48 c7 c1 02 00 00 00    mov    $0x2,%rcx
  a1:   48 89 4f 00             mov    %rcx,0x0(%rdi)
  a5:   c3                      ret

00000000000000a6 <jit_factorial>:
  a6:   48 8b 47 00             mov    0x0(%rdi),%rax
  aa:   48 8b 4f 08             mov    0x8(%rdi),%rcx
  ae:   48 89 ca                mov    %rcx,%rdx
  b1:   48 85 c0                test   %rax,%rax
  b4:   0f 84 1b 00 00 00       je     d5 <jit_factorial+0x2f>
  ba:   e9 00 00 00 00          jmp    bf <jit_factorial+0x19>
  bf:   48 89 c6                mov    %rax,%rsi
  c2:   48 81 ee 01 00 00 00    sub    $0x1,%rsi
  c9:   48 0f af c8             imul   %rax,%rcx
  cd:   48 89 f0                mov    %rsi,%rax
  d0:   e9 d9 ff ff ff          jmp    ae <jit_factorial+0x8>
  d5:   48 89 57 00             mov    %rdx,0x0(%rdi)
  d9:   c3                      ret
```

# Implementing a JIT

## x86 machine abstraction

## Mmaping RWX

## Basic register allocation

## Emitting x86

## Hooking the JIT up to the compiler

## How pg handles ffi or reusing the SYS op

## Profit
