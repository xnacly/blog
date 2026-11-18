---
title: "Making array indexing cheaper in purple gardens VM and JIT"
summary: "Using twos complement to only assert once per idx attempt, instead of twice"
date: 2026-11-15
draft: true
tags:
  - rust
  - pldev
---

Arrays must be indexable, this index has to adhere to being `0<=i<|a|`; where
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

# Simplifying two boundschecks into one

<!-- TODO: write about two complements and how to merge 0<=i<|a| into a single compare -->

# In the IR

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

# In the bytecode virtual machine

Previously, the ir lowered to bytecode instructions:

<!-- TODO: annotate bytecode-->

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

Now its two instructions, meaning we reduced our instruction count by 6,
cutting the dispatch cost by a lot 🤓:

```asm
00000000 <at>:
    ; removed prologue
  0005:    3a 00 01 01    idx r0, r0, r1, #8       ; 4: xs.[i]
  0006:    38 00 00 00    load r0, r0, #0
    ; removed epilogue
```

## Being sidetracked: Dispatch here, dispatch there

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

## Generating op codes

That aside, lets look at the Op code and its packed representation

Lets not get sidetracked as before again, but i use a macro to
generate the rusty representation in the form of an enum and its tag, which
must fit into 6 bits:

```rust
macro_rules! ops {
    (
        // match a single definition
        $(
            // meta tags like doc comments, which are just #[doc]
            $(#[$meta:meta])*

            // definition and tag name
            $name:ident

            // body delimited with {}, matches field containers, is optional via ? to support Halt
            // and Nop (bodyless variants)
            $({ $($body:tt)* })?
        ),*
        $(,)?
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Op {
             $( $(#[$meta])* $name $({ $($body)* })? ),*
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum Tag {
            $($name),*
        }

        impl Tag {
            pub const COUNT: usize = [$(Tag::$name),*].len();
        }

        /// static assertion since tag is 6 bits, meaning 2^6=64 op codes can be represented
        const _: () = assert!(Tag::COUNT <= 64);

        impl Op {
            pub const fn tag(&self) -> Tag {
                match self {
                    $(Self::$name {..} => Tag::$name),*
                }
            }
        }
    }
}
```

So that macro is used to generate the opcode, lets look at IAdd, Idx and Nop, just so you get the gist:

```rust
ops! {
     IAdd {
        dst: u8,
        lhs: u8,
        rhs: u8,
    },
    // [...]

    /// `r[dst] = r[target] + 8 + r[idx] * stride`, the address of element idx. Traps with
    /// [`crate::Anomaly::IndexOutOfBounds`] unless `0 <= r[idx] < len`, len being the array's first
    /// word.
    Idx {
        dst: u8,
        target: u8,
        idx: u8,
        /// distance between elements of array, so addr = arr + 8 + idx * stride
        stride: u16,
    },
    
    // [...]
    Nop,
}
```

## Being sidetracked v2: Packing and unpacking op codes

Since every opcode is a fixed length (32bits), i decided to make the tag 6
bits, fitting 2^6 (64) op code variants or kinds. Every register I made 5 bits,
since the purple garden virtual machine has 32 registers. So something like
`IAdd` is the op class `rrr`, since it uses three registers, meaning i pack it
using a macro helper:

```rust
/// encode different ops into the new packed format, operator classes are the prefix of the macro
/// invocation
///
/// Every opcode starts with tag6 at 0..5
///
/// r        := r5
/// rr       := r5 r5
/// rrr      := r5 r5 r5
/// rrri11   := r5 r5 r5 imm11
/// rri16    := dst5 lhs5 imm16
/// ri21     := dst5 imm21
/// ru21     := r5 idx21
/// t16      := target16
/// u26      := func26
/// rt16     := cond5 target16
/// rrt16    := lhs5 rhs5 target16
/// ri5t16   := lhs5 imm5 target16
/// rru16    := r5 r5 offset16
/// rk1u20   := subject5 kind1 table20
/// rrk1u15  := dst5 subject5 kind1 table15
/// rk2u3u16 := dst5 kind2 align_log(2)3 size16
/// u5u16    := argc5 idx16
/// u16k1    := idx16 returns_double1
macro_rules! encode_packed {
    // [...]
    (rrr,$r1:expr,$r2:expr,$r3:expr) => {
        ($r1 as u32) << 6 | ($r2 as u32) << 11 | ($r3 as u32) << 16
    };
    // [...]
}
```


And unpack it using a method on the `Packed` structure:

```rust{hl_lines=["35-38"]}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Packed(u32);

impl Packed {
    /// [0..5]
    #[inline(always)]
    pub fn tag(&self) -> super::Tag {
        let tag_raw = (self.0 & 0b0011_1111) as u8;
        unsafe { std::mem::transmute::<u8, super::Tag>(tag_raw) }
    }

    #[inline(always)]
    pub fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// `width` bits starting at bit `at`
    #[inline(always)]
    fn bits(self, at: u32, width: u32) -> u32 {
        (self.0 >> at) & ((1 << width) - 1)
    }

    #[inline(always)]
    pub fn r(self) -> u8 {
        self.bits(6, 5) as u8
    }

    #[inline(always)]
    pub fn rr(self) -> (u8, u8) {
        (self.r(), self.bits(11, 5) as u8)
    }

    #[inline(always)]
    pub fn rrr(self) -> (u8, u8, u8) {
        let (r1, r2) = self.rr();
        (r1, r2, self.bits(16, 5) as u8)
    }
}
```

So put together the easiest case (`IAdd`) is encoded:

```rust
impl super::Op {
    pub fn encode(self) -> Packed {
        Packed(
            self.tag() as u32
                | match self {
                    // none
                    crate::op::Op::Ret | crate::op::Op::Halt | crate::op::Op::Nop => 0,
                    // rrr
                    crate::op::Op::IAdd { dst, lhs, rhs } => encode_packed!(rrr, dst, lhs, rhs),

                    // [...] all the other classes
                },
        )
    }
}
```

And decoded:

```rust
pub(super) unsafe fn i_add<const B: bool>(
    vm: V,
    code: *const Packed,
    pc: usize,
    op: Packed,
) -> usize {
    unsafe {
        let (dst, lhs, rhs) = op.rrr();
        let l = r!(vm, lhs).as_int();
        let r = r!(vm, rhs).as_int();
        r_mut!(vm, dst) = Value::from(l + r);
        next!(vm, code, pc.wrapping_add(1))
    }
}
```

## Now: the idx instruction

Previously we saw how the rust enum representing the idx opcode is laid out,
now the packed version, same as before we have a macro for packing and a method
for unpacking. Contrary to `IAdd`, `Idx`'s class is `rrri11`, since it needs
three registers and a 11 bit immediate value:

```rust
macro_rules! encode_packed {
    // [...]
    (rrr,$r1:expr,$r2:expr,$r3:expr) => {
        ($r1 as u32) << 6 | ($r2 as u32) << 11 | ($r3 as u32) << 16
    };
    (rrri11,$r1:expr,$r2:expr,$r3:expr,$imm:expr) => {
        encode_packed!(rrr, $r1, $r2, $r3) | ($imm as u32) << 21
    };
    // [...]
}
```

It is decoded or unpacked with a method of the same name on `Packed`:

 
```rust{hl_lines=["27-30"]}
impl Packed {
    // [...]

    /// `width` bits starting at bit `at`
    #[inline(always)]
    fn bits(self, at: u32, width: u32) -> u32 {
        (self.0 >> at) & ((1 << width) - 1)
    }

    #[inline(always)]
    pub fn r(self) -> u8 {
        self.bits(6, 5) as u8
    }

    #[inline(always)]
    pub fn rr(self) -> (u8, u8) {
        (self.r(), self.bits(11, 5) as u8)
    }

    #[inline(always)]
    pub fn rrr(self) -> (u8, u8, u8) {
        let (r1, r2) = self.rr();
        (r1, r2, self.bits(16, 5) as u8)
    }

    #[inline(always)]
    pub fn rrri11(self) -> (u8, u8, u8, u16) {
        let (r1, r2, r3) = self.rrr();
        (r1, r2, r3, (self.0 >> 21) as u16)
    }
}
```

## Handling in the handler

<!-- TODO: write about the handler -->

# In the x86 jit backend

Whereas previously this required a bucketload of instructions:

> Btw thank [samuelscheit](https://samuelscheit.com/) for the x86 assembly
> annotations, he was buggering me how no one understands this without comments
> :)

<!-- TODO: annotate asm -->

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

Our example is a pretty uncomplicated heavy array indexing focused benchmark,
which is, ofc a microbenchmark:

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
