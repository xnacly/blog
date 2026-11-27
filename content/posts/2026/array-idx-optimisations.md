---
title: "Making array indexing cheaper in purple gardens VM and JIT"
summary: "Using 2s complement for merging work & taking detours into dispatch and opcode design"
date: 2026-11-15
math: true
tags:
  - rust
  - pldev
---

Welcome to yet another blog article about a single topic hijacked into a dev
log kind of situation with some detours and some microbenchmarks, have fun :)

Sooooooo: Arrays must be indexable, the index has to adhere to being
`0<=i<|a|`; where `||` is the length of the array `a`. Checking this is
regarded as a bounds check ([wikipedia -Bounds
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

# Simplifying two bounds checks into one by knowing 2complement

{{<callout type="TL;DR - I know math 🤓 - Info">}}
Two cases, assuming i and len are i64 values and len is nonnegative:

- A: negative index:

$$
\begin{aligned}
i < 0 &\implies i \bmod 2^{64} \geq 2^{63} \\
0 \leq len &\implies len < 2^{63} \\
&\implies \textrm{cast}_{u64}(i) > \textrm{cast}_{u64}(len)
\end{aligned}
$$

- B: nonnegative index:

$$
\begin{aligned}
i \geq 0 &\implies \textrm{cast}_{u64}(i) = i \\
&\implies \textrm{cast}_{u64}(i) < \textrm{cast}_{u64}(len)
\Leftrightarrow i < len
\end{aligned}
$$

Thus, combined:
$$
\begin{aligned}
-1 < i < len
&\Leftrightarrow
\textrm{cast}_{u64}(i) < \textrm{cast}_{u64}(len)
\end{aligned}
$$
{{</callout>}}

For the sake of explaining the simplification, I will not show this with 32 bit
integers, but rather with 8 bit. In general, fixed width integers are
represented with the [two
complements](https://en.wikipedia.org/wiki/Two%27s_complement) method, meaning
you have a numeric value assigned to each bit, for instance 12 is formed by
setting the bits for 4 and 8, but not for 1 and 2, in a table it would be:

| twos complement | 2^7 | 2^6 | 2^5 | 2^4 | 2^3 | 2^2 | 2^1 | 2^0 |
| --------------- | --- | --- | --- | --- | --- | --- | --- | --- |
| decimal         | 128 | 64  | 32  | 16  | 8   | 4   | 2   | 1   |
| -               |     |     |     |     |     |     |     |     |
| 12              | 0   | 0   | 0   | 0   | 1   | 1   | 0   | 0   |

Which is the sum of its set bits value in the twos complement table, which is
8+4, thus 12. However this is only valid for unsigned 8 bit integers,
representing 0<=x<=255 (256) different values. For signed integers the [most significant
bit](https://en.wikipedia.org/wiki/Bit_numbering) has a negative weight, while
all others are the same numbers we are "adding" to this starting point. So -12
would be first msb set, so -128 as a base, whereas then the bits for 64, 32 and
4 are set so we arrive at -12 (-128+64+32+16+4=-12):

| twos complement | -(2^7) | 2^6 | 2^5 | 2^4 | 2^3 | 2^2 | 2^1 | 2^0 |
| --------------- | ------ | --- | --- | --- | --- | --- | --- | --- |
| decimal         | -128   | 64  | 32  | 16  | 8   | 4   | 2   | 1   |
| -               |        |     |     |     |     |     |     |     |
| -12             | 1      | 1   | 1   | 1   | 0   | 1   | 0   | 0   |

However, a simple cast in the sense of `-12 as u8` results not in 12, but in
the unsigned interpretation of -12's bits, specifically seeing 0b11110100,
which results in 128+64+32+16+4=244.

In summary: casting a negative signed integer to its equal bit sized unsigned
counterpart produces very large numbers, thus satisfing our requirement to make
the bound check in a single comparison.

This behaviour we can exploit to merge the two comparisons in both the bytecode
and the x86 jitted output from:

```rust
-1 < i && i < len
```

To

```rust
(i as u64) < (len as u64)
```

{{<callout type="Info">}}
My quick verification to make sure:

```rust
fn main() {
    let len = 2;
    std::env::args()
        .filter_map(|n| n.parse::<i64>().ok())
        .for_each(|i| {
            let base = -1 < i && i < len;
            let opt = (i as u64) < (len as u64);
            assert_eq!(base, opt);
        });
}
```

```shell
cargo run 12 15 1 0 -1000
```

{{</callout>}}

# In the Immediate representation

Thus, let me introduce the `Index` ir instruction, merging the bounds check,
offset calculation and offset usage a single instruction:

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

```asm
00000000 <at>:
    ; removed prologue

    ; fetch r0+0 (array length) into r2
  0005:    b8 00 00 00    load r2, r0, #0          ; 4: xs.[i]
    ; check r1 (idx) > -1 into r3
  0006:    d0 08 ff ff    igt_imm r3, r1, #-1
    ; trap if !r3
  0007:    fb 08 00 00    assert r3, InBounds
    ; check r1 < r2 (idx < arrlen) into r2
  0008:    8c 08 02 00    ilt r2, r1, r2
    ; trap if !r2
  0009:    bb 08 00 00    assert r2, InBounds
    ; r1 mul 8 (idx*type size) into r1
  000a:    45 08 08 00    imul_imm r1, r1, #8
    ; r0+r1 (arr+offset) into r0
  000b:    00 00 01 00    iadd r0, r0, r1
    ; fetch value from r0
  000c:    38 00 08 00    load r0, r0, #8
    ; removed epilogue
```

Now its two instructions, meaning we reduced our instruction count by 6,
cutting the dispatch cost by a lot 🤓:

```asm
00000000 <at>:
    ; removed prologue

    ; idx r0 with r1 with typesize 8 into r0 (arr[idx])
  0005:    3a 00 01 01    idx r0, r0, r1, #8       ; 4: xs.[i]
    ; fetch value from r0
  0006:    38 00 00 00    load r0, r0, #0
    ; removed epilogue
```

## Being sidetracked: Dispatch here, dispatch there

Btw, purple garden uses the
[become](https://doc.rust-lang.org/stable/std/keyword.become.html) proposal for
tailcalling op code handlers, meaning instead of jumping back to the loop head,
decoding the op code and then jumping to the handler. Instead, become decodes
the op and the jmp location and then jumps to it, making dispatch less costly
due to less indirection while jumping from opcode handler to opcode handler,
see the following setup:

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

    /// `r[dst] = r[target] + 8 + r[idx] * stride`, the address of element idx.
    /// Traps with [`crate::Anomaly::IndexOutOfBounds`] unless `0 <= r[idx] < len`,
    /// len being the array's first word of an array
    Idx {
        dst: u8,
        target: u8,
        idx: u8,
        /// distance between elements of array,
        /// so addr = arr + 8 + idx * stride
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
                    crate::op::Op::Ret
                    | crate::op::Op::Halt
                    | crate::op::Op::Nop => 0,
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

Thus encoding via:

```rust
// rrri11
crate::op::Op::Idx {
    dst,
    target,
    idx,
    stride,
} => encode_packed!(rrri11, dst, target, idx, stride),
```

Meaning we decode and execute in the handler:

```rust
use super::*;

pub(super) unsafe fn idx<const B: bool>(
    vm: V,
    code: *const Packed,
    pc: usize,
    op: Packed,
) -> usize {
    unsafe {
        // decode op content
        let (dst, target, idx, stride) = op.rrri11();
        // fetch numeric idx from rIDX as int
        // could be just 5 or something
        let idx = r!(vm, idx).as_int();
        // fetch rTARGET as a ptr, for instance an array
        let ptr = r!(vm, target).as_ptr::<u8>();

        // idx has to uphold 0<=idx<len(src),
        // where len(src) is ptr+0, see memory layout
        // of arrays
        trap_if!(
            vm,
            idx as u64 >= *(ptr as *const u64),
            Anomaly::IndexOutOfBounds { pc }
        );

        let offset = 8 + idx as usize * stride as usize;
        // equiv to c like:
        //      reg[dst] = *(Value)(arr+8+idx*stride)
        // where stride is the size of the elements type
        // and 8 is the skip over the first word of the ptr,
        // which is the length of an array
        r_mut!(vm, dst) = Value::from_ptr(ptr.add(offset));
        next!(vm, code, pc.wrapping_add(1))
    }
}
```

Visualising with both vm registers and memory, assuming we are executing:

```garden
let arr = [161 187]
# focusing on:
let idx2 = arr.[1]
```

Eqiv to loading the idx into r1, while the array reference is in r0:

```asm
00000000 <entry>:
    ; removed array creation
  0007:    5c 08 00 00    load_imm r1, #1
  0008:    3a 00 01 01    idx r0, r0, r1, #8
```

```text
+------------ Vm -----------+
|     | u64 | u64 | u64 |   |
|   r | r0  | r1  | r2  |   |
+-------^-----^-------------+
        |     |
        |     idx (Int)
        |
       target (&Array<Int>)
              |
              _
---------- Vm Heap -----------
              |
              +-------+
                      |
                      v
        +----------- Arr -------------+
        | component: len  |pos0 |pos1 |
        | layout:    [2]  [161] [187] |
        +-----------------------------+
```

# In the x86 jit backend

Whereas previously this required a bucketload of instructions:

> Btw thank [samuelscheit](https://samuelscheit.com/) for the x86 assembly
> annotations, he was buggering me how no one understands this without comments
> :)

```nasm
0000000000000000 <jit_at>:
    ; removed prologue

    ; rsi=r0 (arr ptr), rdx=r1 (idx), rbx=vm ptr

    ; fetch rsi+0 (array length) into r8
  29:   4c 8b 46 00             mov    0x0(%rsi),%r8
    ; compare rdx (idx) with -1
  2d:   48 81 fa ff ff ff ff    cmp    $0xffffffffffffffff,%rdx
    ; zero r9, mov instead of xor, so xor doesnt clobber cmp flag(s)
  34:   49 c7 c1 00 00 00 00    mov    $0x0,%r9
    ; r9b=1 if idx > -1
  3b:   41 0f 9f c1             setg   %r9b
    ; check r9 != 0
  3f:   4d 85 c9                test   %r9,%r9
    ; if idx > -1, jmp over trap, continue at 61
  42:   0f 85 19 00 00 00       jne    61 <jit_at+0x61>
    ; vm as first arg
  48:   48 89 df                mov    %rbx,%rdi
    ; anomaly kind as second arg (to communicate trap is InBounds kind)
  4b:   48 be 01 00 00 00 00    movabs $0x1,%rsi
  52:   00 00 00
    ; absolute addr of jit_trap_assert in rax
  55:   48 b8 00 00 00 00 00    movabs $0x0,%rax
  5c:   00 00 00
                        57: R_X86_64_64 jit_trap_assert
  5f:   ff d0                   call   *%rax
    ; compare rdx (idx) with r8 (array length)
  61:   4c 39 c2                cmp    %r8,%rdx
    ; zero r8, flag preserving
  64:   49 c7 c0 00 00 00 00    mov    $0x0,%r8
    ; r8b=1 if idx < len
  6b:   41 0f 9c c0             setl   %r8b
    ; check r8 != 0
  6f:   4d 85 c0                test   %r8,%r8
    ; if idx < len, skip over trap, continue at 91
  72:   0f 85 19 00 00 00       jne    91 <jit_at+0x91>
    ; same trap setup and call as above
  78:   48 89 df                mov    %rbx,%rdi
  7b:   48 be 01 00 00 00 00    movabs $0x1,%rsi
  82:   00 00 00
  85:   48 b8 00 00 00 00 00    movabs $0x0,%rax
  8c:   00 00 00
                        87: R_X86_64_64 jit_trap_assert
  8f:   ff d0                   call   *%rax
    ; rdx mul 8 (idx*type size) into r8
  91:   4c 69 c2 08 00 00 00    imul   $0x8,%rdx,%r8
    ; rsi+r8 (arr+offset) into rsi
  98:   4c 01 c6                add    %r8,%rsi
    ; fetch value from rsi+8 (skipping the length) into rsi
  9b:   48 8b 76 08             mov    0x8(%rsi),%rsi
    ; removed epilogue
```

We now instead lower the `Index` instruction to:

```nasm
0000000000000000 <jit_at>:
    ; removed prologue
    ; rsi=r0 (arr ptr), rdx=r1 (idx), rbx=vm ptr

    ; compare rdx (idx) with rsi+0 (array len)
  29:   48 3b 56 00             cmp    0x0(%rsi),%rdx
    ; unsigned idx < len holds, skip trap, continue at 4c
    ; (jb is the unsigned below, so a negative idx is huge
    ; and fails the check, as i explained in the 2complements section)
  2d:   0f 82 19 00 00 00       jb     4c <jit_at+0x4c>
    ; vm ptr as first arg
  33:   48 89 df                mov    %rbx,%rdi
    ; anomaly kind as second arg
  36:   48 be 01 00 00 00 00    movabs $0x1,%rsi
  3d:   00 00 00
    ; absolute addr of jit_trap_assert in rax
  40:   48 b8 00 00 00 00 00    movabs $0x0,%rax
  47:   00 00 00
                        42: R_X86_64_64 jit_trap_assert
    ; trap
  4a:   ff d0                   call   *%rax
    ; rsi+rdx*8+8 (arr+idx*type size+length skip) into rsi,
    ; (this merges the offset computation in a single instruction, aitn that
    ; nice)
  4c:   48 8d 74 d6 08          lea    0x8(%rsi,%rdx,8),%rsi
    ; fetch value from rsi
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

## Results for Interpreter and Jit

| Interpreter (`--no-jit`)   | Before        | After       | Change        |
| -------------------------- | ------------- | ----------- | ------------- |
| Wall time                  | 95.6 ms       | 59.9 ms     | −37.4% (1.6x) |
| Instructions               | 1,374,124,846 | 836,515,352 | −39.1%        |
| Cycles                     | 381,011,434   | 234,946,985 | −38.3%        |
| Branches                   | 112,984,474   | 68,182,320  | −39.7%        |
| Branch misses              | 212,833       | 212,073     | 0             |
| IPC                        | 3.61          | 3.56        | −0.05         |

| JIT                        | Before      | After      | Change        |
| -------------------------- | ----------- | ---------- | ------------- |
| Wall time                  | 11.5 ms     | 7.9 ms     | −31.0% (1.4x) |
| Instructions               | 140,113,697 | 76,103,420 | −45.7%        |
| Cycles                     | 42,189,251  | 27,802,005 | −34.1%        |
| Branches                   | 26,983,190  | 20,581,065 | −23.7%        |
| Branch misses              | 211,863     | 211,747    | 0             |
| IPC                        | 3.32        | 2.74       | −0.58         |

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
