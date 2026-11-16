---
title: "Making array indexing a bit less costly for purple garden"
summary: "Using twos complement to only assert once per idx attempt, instead of twice"
date: 2026-11-15
draft: true
tags:
  - rust
  - pldev
---

Arrays must be indexable, this index has to adhere to being `0<=i<=|a|`; where
`||` is the length of the array `a`. Checking this is regarded as a bounds
check ([wikipedia -Bounds
checking](https://en.wikipedia.org/wiki/Bounds_checking))

# The obligatory gardening example

Lets consider the following
[purple-garden](https://github.com/xnacly/purple-garden) snippet:

```garden
import "io"
fn at(xs:Array<Int> i:Int) Int {
    // just here to stop inlining :)
    io.println(i)
    xs.[i]
}
io.println(at([1 2 3] 1))
```

Disregarding the `io.println` calls and the seemingly unnecessary indirection of
indexing via `at` [^opt-workaround], we can inspect the resulting intermedite
representation of `at`:

```llvm
// at
fn f1(%v0:Array<Int>, %v1:Int) -> Int {
    b0(%v0, %v1):
        ; just here to stop inlining
        %v2:Void = Sys io.println_int(%v1)

        ; load first word of array, which is its length
        %v3:Int = Load %v0+0

        ; assert idx > -1
        %v5:Bool = IGt %v1, -1
        %v6:Void = Assert(InBounds) %v5

        ; assert len > idx
        %v7:Bool = ILt %v1, %v3
        %v8:Void = Assert(InBounds) %v7

        ; calculate offset by type size (8)
        %v10:Int = IMul %v1, 8
        ; add offset to arr ptr
        %v11:Ptr = IAdd %v0, %v10
        ; fetch arrayptr+offset+1 (skipping length word)
        %v12:Int = Load %v11+8
        ret %v12
}
```

# Rethinking the approach

The attentive reader will have realised this produces 8 instructions per index,
which for the bytecode backend, where dispatch dominates, is very costly, even
more so than in the x86 backend, where it still isnt free though.

## In the IR

Thus, let me introduce the `Index` ir instruction, merging the bounds check,
offset calculation, offset usage and loading the result at said offset into a
single instruction:

## In the bytecode virtual machine

Previously, the ir lowered to bytecode instructions:

```asm
00000000 <at>:
    ; removed prologue
  0005:    b8 00 00 00    load r2, r0, #0          ; 4: xs.[i]
  0006:    d0 08 ff ff    igt_imm r3, r1, #-1
  0007:    fb 08 00 00    assert r3, InBounds
  0008:    8c 08 02 00    ilt r2, r1, r2
  0009:    bb 08 00 00    assert r2, InBounds
  000a:    45 08 08 00    imul_imm r1, r1, #8
  000b:    00 00 01 00    iadd r0, r0, r1
  000c:    38 00 08 00    load r0, r0, #8
    ; removed epilogue
```

Now its a single instruction, meaning we 1/8th our instruction count, cutting
the dispatch cost to a single instruction 🤓:

```asm

```

You know, worst case dispatch cost (randomized) is ~35 cycles /
8.9ns, while perfect dispatch (only NOP) is around 3 cycles / 0.71ns:

| Benchmark                | Time    | Per op  | Cycles per op |
| ------------------------ | ------- | ------- | ------------- |
| `bench_random_dispatch`  | 85.8 ms | 8.58 ns | ~35           |
| `bench_uniform_dispatch` | 7.14 ms | 0.71 ns | ~3            |

## In the x86 jit backend

Whereas previously this required a bucketload of instructions:

```nasm
0000000000000000 <jit_at>:
    ; removed prologue
  29:   4c 8b 46 00             mov    0x0(%rsi),%r8
  2d:   48 81 fa ff ff ff ff    cmp    $0xffffffffffffffff,%rdx
  34:   49 c7 c1 00 00 00 00    mov    $0x0,%r9
  3b:   41 0f 9f c1             setg   %r9b
  3f:   4d 85 c9                test   %r9,%r9
  42:   0f 85 19 00 00 00       jne    61 <jit_at+0x61>
  48:   48 89 df                mov    %rbx,%rdi
  4b:   48 be 01 00 00 00 00    movabs $0x1,%rsi
  52:   00 00 00
  55:   48 b8 00 00 00 00 00    movabs $0x0,%rax
  5c:   00 00 00
                        57: R_X86_64_64 jit_trap_assert
  5f:   ff d0                   call   *%rax
  61:   4c 39 c2                cmp    %r8,%rdx
  64:   49 c7 c0 00 00 00 00    mov    $0x0,%r8
  6b:   41 0f 9c c0             setl   %r8b
  6f:   4d 85 c0                test   %r8,%r8
  72:   0f 85 19 00 00 00       jne    91 <jit_at+0x91>
  78:   48 89 df                mov    %rbx,%rdi
  7b:   48 be 01 00 00 00 00    movabs $0x1,%rsi
  82:   00 00 00
  85:   48 b8 00 00 00 00 00    movabs $0x0,%rax
  8c:   00 00 00
                        87: R_X86_64_64 jit_trap_assert
  8f:   ff d0                   call   *%rax
  91:   4c 69 c2 08 00 00 00    imul   $0x8,%rdx,%r8
  98:   4c 01 c6                add    %r8,%rsi
  9b:   48 8b 76 08             mov    0x8(%rsi),%rsi
    ; removed epilogue
```

We now instead lower the `Index` instruction to:

-

# Benchmark(s)

Our example is a pretty uncomplicated heavy array indexing focused benchmark:

```garden
# Sums an array literal in a tight recursive loop.
# Every xs.[i] produces bounds check, showing indexing costs
import "testing"

#! acc plus xs.[j] for j in [i, 32).
fn sweep(xs:Array<Int> i:Int acc:Int) Int {
    match {
        i == 32 { acc }
        { sweep(xs i + 1 acc + xs.[i]) }
    }
}

#! Sum of k sweeps
fn rounds(xs:Array<Int> k:Int acc:Int) Int {
    match {
        k == 0 { acc }
        { rounds(xs k - 1 acc + sweep(xs 0 0)) }
    }
}

#! b blocks of 2000 rounds
fn blocks(xs:Array<Int> b:Int acc:Int) Int {
    match {
        b == 0 { acc }
        { blocks(xs b - 1 acc + rounds(xs 2000 0)) }
    }
}

let xs = [11 48 85 21 58 95 31 68 4 41 78 14 51 88 24 61 98 34 71 7 44 81 17 54 91 27 64 0 37 74 10 47]
testing.assert(blocks(xs 100 0) == 306800000)
```

And all numbers were computed on:

```shell
$ inxi
CPU: 8-core AMD Ryzen 7 3700X (-MT MCP-)
speed/min/max: 4047/2200/4979 MHz
Kernel: 7.2.14-arch1-1 x86_64 Up: 1d 5h 18m
Mem: 21.27/31.26 GiB (68.0%) Storage: 2.27 TiB (38.6% used)
Procs: 506 Shell: fish inxi: 3.3.41
```

## Baseline

|     | Wall time | Instructions  | Cycles      | Branches    | Branch misses |
| --- | --------- | ------------- | ----------- | ----------- | ------------- |
| VM  | ~96 ms    | 1,374,124,575 | 394,652,180 | 112,984,439 | 225,353       |
| JIT | 12.0 ms   | 140,112,693   | 43,480,187  | 26,982,943  | 211,910       |

## Postwork

[^opt-workaround]:
    i added, so the preexisting optimisation
    passes dont fuse the whole thing into a single load of the imm value at the
    idx of the arr:

    ```llvm
    // entry
    fn f0() -> Void {
        b0():
            %v2:Int = 1
            %v16:Void = Sys io.println_int(%v2)
            ret %v16
    }
    ```
