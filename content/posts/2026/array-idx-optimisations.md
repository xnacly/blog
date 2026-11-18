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

```llvm
// at
fn f1(%v0:Array<Int>, %v1:Int) -> Int {
        b0(%v0, %v1):
                %v2:Void = Sys io.println_int(%v1)
                %v3:Ptr<Int> = Index %v0, %v1
                %v4:Int = Load %v3+0
                ret %v4
}
```

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

Now its a single instruction, meaning we reduced our instruction count by 6,
cutting the dispatch cost to a single instruction 🤓:

```asm
00000000 <at>:
    ; removed prologue
  0005:    3a 00 01 01    idx r0, r0, r1, #8       ; 4: xs.[i]
  0006:    38 00 00 00    load r0, r0, #0
    ; removed epilogue
```

You know, worst case dispatch cost (randomized) is ~35 cycles /
8.9ns, while perfect dispatch (only NOP) is around 3 cycles / 0.71ns:

| Benchmark                | Time    | Per op  | Cycles per op |
| ------------------------ | ------- | ------- | ------------- |
| `bench_random_dispatch`  | 85.8 ms | 8.58 ns | ~35           |
| `bench_uniform_dispatch` | 7.14 ms | 0.71 ns | ~3            |

Meaning approximately, for the worst predicted dispatch we reduced the cost by
210 cycles / 52ns or for the best case reduced it by 18cycles / 4.26ns PER
index instruction.

Btw, purple garden uses the
[become](https://doc.rust-lang.org/stable/std/keyword.become.html) proposal for
tailcalling op code handlers, meaning instead of jumping back to the loop head,
decoding the op code and then jumping to the handler. Instead, become decodes
the op and the jmp location and then jumps to it, making dispatch less costly
due to less indirection and cpu branch mispredictions while jumping from opcode
handler to opcode handler, see the following setup:

```rust
type V = *mut Vm<'static>;
type Handler = unsafe fn(V, *const Packed, usize, Packed) -> usize;
struct Handlers<const B: bool>;

impl<const B: bool> Handlers<B> {
    const TABLE: [Handler; 64] = {
        let mut table: [Handler; 64] = [halt::<B>; 64];
        let mut i = 0;
        while i < Tag::COUNT {
            table[i] = Self::handler(unsafe { std::mem::transmute::<u8, Tag>(i as u8) });
            i += 1;
        }
        table
    };

    const fn handler(tag: Tag) -> Handler {
        match tag {
            // [...]
            Tag::Idx => rrri11::idx::<B>,
            Tag::Nop => nop::<B>,
        }
    }
}

macro_rules! next {
    ($vm:ident, $code:ident, $pc:expr) => {{
        let pc = $pc;
        let op = *$code.add(pc);
        become (Handlers::<B>::TABLE[op.tag() as usize])($vm as V, $code, pc, op)
    }};
}

pub(super) unsafe fn enter<const B: bool>(
    vm: V,
    code: *const Packed,
    pc: usize,
) -> Result<usize, Anomaly> {
    unsafe {
        let op = *code.add(pc);
        let pc = (Handlers::<B>::TABLE[op.tag() as usize])(vm, code, pc, op);
        (*vm).pending_trap.take().map_or(Ok(pc), Err)
    }
}
```


For instance, the NOP op handler is defined as:

```rust
unsafe fn nop<const B: bool>(vm: V, code: *const Packed, pc: usize, _op: Packed) -> usize {
    unsafe { next!(vm, code, pc.wrapping_add(1)) }
}
```

Meaning the dispatch compiles to a solid 6 instructions:

```nasm
mov    ecx,DWORD PTR [rsi+rdx*4+0x4]   ; op = code[pc+1]
inc    rdx                             ; pc += 1
mov    eax,ecx
and    eax,0x3f                        ; tag = op & 63
lea    r8,[rip+TABLE]
jmp    QWORD PTR [r8+rax*8]            ; become TABLE[tag](vm, code, pc, op)
```

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

```nasm
0000000000000000 <jit_at>:
    ; removed prologue
  29:   48 3b 56 00             cmp    0x0(%rsi),%rdx
  2d:   0f 82 19 00 00 00       jb     4c <jit_at+0x4c>
  33:   48 89 df                mov    %rbx,%rdi
  36:   48 be 01 00 00 00 00    movabs $0x1,%rsi
  3d:   00 00 00
  40:   48 b8 00 00 00 00 00    movabs $0x0,%rax
  47:   00 00 00
                        42: R_X86_64_64 jit_trap_assert
  4a:   ff d0                   call   *%rax
  4c:   48 8d 74 d6 08          lea    0x8(%rsi,%rdx,8),%rsi
  51:   48 8b 76 00             mov    0x0(%rsi),%rsi
    ; removed epilogue
```

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
| VM  | 96 ms     | 1,374,124,575 | 394,652,180 | 112,984,439 | 225,353       |
| JIT | 12.0 ms   | 140,112,693   | 43,480,187  | 26,982,943  | 211,910       |

## Postwork - Bytecode

| VM            | Before        | After       | Change        |
| ------------- | ------------- | ----------- | ------------- |
| Wall time     | 95.4 ms       | 59.7 ms     | −37.5% (1.6x) |
| Instructions  | 1,374,125,067 | 836,514,290 | −39.1%        |
| Cycles        | 382,010,097   | 236,250,236 | −38.2%        |
| Branches      | 112,984,570   | 68,182,029  | −39.7%        |
| Branch misses | 212,093       | 211,680     |               |

## JIT - Bytecode

| JIT           | Before      | After      | Change        |
| ------------- | ----------- | ---------- | ------------- |
| Wall time     | 11.4 ms     | 7.8 ms     | −31.0% (1.4x) |
| Instructions  | 140,111,753 | 76,100,879 | −45.7%        |
| Cycles        | 42,099,555  | 27,917,091 | −33.7%        |
| Branches      | 26,982,657  | 20,580,313 | −23.7%        |
| Branch misses | 211,306     | 211,205    |               |

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
