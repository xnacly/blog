---
title: "Interpreter spill stack on the process stack & trait::Allocator for stack allocations"
summary: "Using the new Allocators to move vm spill from the heap to the process stack"
date: 2026-10-10T12:41:46+02:00
tags:
  - rust
  - pldev
---

I'm currently still working on my scripting language,
[purple-garden](https://github.com/xnacly/purple-garden), and wanted to port
all stages of the compilation pipeline over to the new allocator trait (for a
list of reasons, for instance i use scratch storage in all stages for temporary
allocs and would like to both reuse and optimise this memory area for locality
and cheap allocs) one of these zig style inspired allocators is the
`StackAllocator` which ill explain in this article and use to optimise the
register spilling and restore to the virtual machine stack (the others are
`PageAlloc`, `BumpAlloc<A>` and `MetricAllocator<A>`).

> These changes dont really affect the general purpose performance of purple
> garden anymore, since most of the speed is squeezed out of the runtime via
> the JIT (only x86 for now)

# Some prerequisites

## trait::Allocator

The
[trait::Allocator](https://doc.rust-lang.org/nightly/std/alloc/trait.Allocator.html)
proposal was recently
[stabilised](https://github.com/rust-lang/rust/pull/156882) in rust version
1.100 which introduces a new unsafe trait and a few functions taking these
allocators, for instance `{Vec,Box,HashMap,HashSet}::new_in()`. These functions
then allocate their memory into the passed in allocator and thus can now live
in whatever memory region the allocator is backed by:

```rust
pub unsafe trait Allocator {
    fn allocate(
        &self,
        layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError>;

    unsafe fn deallocate(
        &self,
        ptr: NonNull<u8>,
        layout: Layout,
    );

    fn allocate_zeroed(
        &self,
        layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError>

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError>

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError>

    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError>
}
```

## Purple garden virtual machine

Purple gardens interpreter and thus the virtual machine are register based (for
performance reasons) and therefore may run out of space in the register. This
is indicated by the bytecode register allocator for both running out of
register and also extending values lifetimes over functions, for instance
consider the humble `fib` function:

```garden
#! Compute Fibonacci numbers with the classic doubly-recursive definition.
fn fib(n:Int) Int {
    match {
        n == 0 { 0 }
        n == 1 { 1 }
        { fib(n - 1) + fib(n - 2) }
    }
}
```

And its garden disassembly:

```asm
; purple-garden --no-jit -D examples/fib.garden
00000000 <fib>:
  ; 8: fn fib(n:Int) Int {
  0000:    push r1
  ; 10: n == 0 { 0 }
  0001:    jmpne_imm r0, #0, 0006 <fib.bb_0006>
  0002:    load_imm r1, #0
  0003:    mov r0, r1
  0004:    pop r1
  0005:    ret

00000006 <fib.bb_0006>:
  ; 11: n == 1 { 1 }
  0006:    jmpne_imm r0, #1, 000b <fib.bb_000b>
  0007:    load_imm r1, #1
  0008:    mov r0, r1
  0009:    pop r1
  000a:    ret

0000000b <fib.bb_000b>:
  ; 12: { fib(n - 1) + fib(n - 2) }
  000b:    isub_imm r1, r0, #1
  000c:    push r0
  000d:    mov r0, r1
  000e:    call 0000 <fib>
  000f:    mov r1, r0
  0010:    pop r0
  0011:    isub_imm r0, r0, #2
  0012:    call 0000 <fib>
  0013:    iadd r0, r1, r0
  0014:    pop r1
  0015:    ret
```

In this example the function prologue (`push r1`) and epilogue (`pop r1`) serve
the purpose of saving and restoring callee saved registers the recursive calls
would clobber.

{{<callout type="Info - Purple garden calling convention excursion">}}
Registers are split into two zones (similar to x86 and aarch64):

- `r0..r{n}` is considered the argument zone, while r0 is also the return
  slots, these are caller saved so a caller with a live value in this range must
  spill and restore around the call
- `r{n+1}..r{max}` are the callee saved registers, meaning the callee doesnt clobber them

The fib example would be better by putting constants into better fitting
registers, for instance r0 instead of the indirection through r1 and only
pushing in the branches really clobbering r1, but this is
[zukunftsmusik](https://en.wiktionary.org/wiki/Zukunftsmusik), as the germans
say :)
{{</callout>}}

## Previous Vm stack, {Push,Pop}{2,3} and their handlers

The stack interaction opcodes for the vm are defined as:

```rust
Push { src: u8, },
Push2 { a: u8, b: u8, },
Push3 { a: u8, b: u8, c: u8, },
Pop { dst: u8, },
Pop2 { a: u8, b: u8, },
Pop3 { a: u8, b: u8, c: u8, },
```

The simplest stack i could think of when implementing the virtual machine was
using `Vec<Value>` for `Vm::spilled`, preallocating it with 4096 values and
pushing and popping with unchecked mut writes and reads:

```rust
Op::Push { src } => {
    // whole handler basically
    // equivalent to self.spilled.push(*r!(src))

    let len = self.spilled.len();

    if std::hint::unlikely(
        len + 1 > self.spilled.capacity()) {
        self.spilled.reserve(1);
    }

    unsafe {
        // use mut pointer, advance to length
        let dst = self.spilled.as_mut_ptr().add(len);
        // write value in register src into spilled[len]
        dst.write(*r!(src));
        self.spilled.set_len(len + 1);
    }
}

// ...

Op::Pop { dst } => unsafe {
    // whole handler basically equivalent to
    // *r_mut!(dst) = self.spilled.pop();

    let len = self.spilled.len();
    let ptr = self.spilled.as_ptr();
    debug_assert!(len >= 1);
    r_mut!(dst) = ptr.add(len - 1).read();
    self.spilled.set_len(len - 1);
}
```

Then i also added the fused {Push,Pop}{2,3} merging two and three stack
interactions into a single operation without bounds check, for instance
`Pop3`:

```rust
Op::Pop3 { a, b, c } => unsafe {
    let len = self.spilled.len();
    let ptr = self.spilled.as_ptr();
    debug_assert!(len >= 3);
    r_mut!(a) = ptr.add(len - 1).read();
    r_mut!(b) = ptr.add(len - 2).read();
    r_mut!(c) = ptr.add(len - 3).read();
    self.spilled.set_len(len - 3);
}
```

# StackAllocator

Technically just an allocator allocating into an already allocated buffer that
just happens to be on the stack :O (I guess naming this BufferAllocator or
something similar would be more useful, but im using it for allocating on the
stack so its fine). For instance with a buffer allocated on the stack by (us)
the caller, like so:

```rust
let mut buf = [MaybeUninit::<u8>::uninit(), 1024];
let alloc = StackAlloc::new(&mut spillstack);
let mut vec_on_the_stack = Vec::new_in(&alloc);
vec_on_the_stack.push(787);
vec_on_the_stack.push(161);
vec_on_the_stack.push(256);
let box_on_the_top = Box::new_in(0xDEADAFFE, &alloc)
```

StackAlloc doesnt consume or use the handed in buffer other than keeping it
around as a marker for lifetime purposes so the compiler makes sure the data
doesnt outlive our data living in it. It then has a base, named block, a cap
for bounds checks and top for advancing.

```rust
pub struct StackAlloc<'buf> {
    /// base ptr
    block: NonNull<u8>,
    /// buffer size
    cap: usize,
    /// next free byte
    top: Cell<usize>,
    /// marker for lifetime >:(
    _buf: PhantomData<&'buf mut [MaybeUninit<u8>]>,
}
```

The next chapter will explain the Allocator trait impl, but at a high level the allocator works by:

1. find the `start`, which is `block`+`top`; rounded up to alignment (16 bytes, see "Tip" below)
2. find the `end` of the allocation; requested size rounded up to alignment, added to `start`
3. check if enough space in buffer; `end > cap`
4. advance `top` to `end`
5. return `block`+`start`, sliced to request size to omit alignment

{{<callout type="Tip - Why alignment is 16 bytes">}}
StackAllocator uses a 16 byte alignment to fix the issue of multiple alignments
leaving padding behind, for instance: 3 bytes at offset 0, then 8 bytes aligned
to 8 at offset 8. Freeing the 8 bytes moves `top` back to 8, but the 3 bytes
end at 3, so they never count as the top allocation again and are lost until
the allocator is reset. With rounding up to 16 byte alignment, every allocation
aligned up to 16 starts right at `top` and frees in reverse work.

The methods supporting the virtual machine stack dont use this abstraction,
since all values in the vm are a uniform 8 bytes.
{{</callout>}}

## Impl trait::Allocator

```rust
impl<'buf> StackAlloc<'buf> {
    pub fn new(buf: &'buf mut [MaybeUninit<u8>]) -> Self {
        let skip = buf.as_ptr().align_offset(UPROUND).min(buf.len());
        let block = NonNull::from(&mut buf[skip..]).cast::<u8>();
        Self {
            block,
            cap: (buf.len() - skip) / UPROUND * UPROUND,
            top: Cell::new(0),
            _buf: PhantomData,
        }
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        self.top.get()
    }

    pub fn reset(&mut self) {
        self.top.set(0);
    }

    fn offset(&self, ptr: NonNull<u8>) -> usize {
        ptr.as_ptr() as usize - self.block.as_ptr() as usize
    }

    fn is_top(&self, ptr: NonNull<u8>, layout: Layout) -> bool {
        self.offset(ptr) + granules(layout.size()) == self.top.get()
    }
}

// singular buffer borrow, so sending is safe
unsafe impl Send for StackAlloc<'_> {}
```

depth, reset, offset and is_top are used in the allocator trait impl and the vm stack methods:

```rust

pub const UPROUND: usize = 16;

#[inline(always)]
fn granules(size: usize) -> usize {
    size.next_multiple_of(UPROUND)
}

unsafe impl Allocator for StackAlloc<'_> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let base = self.block.as_ptr() as usize;
        let start = (base + self.top.get()).next_multiple_of(layout.align()) - base;
        let end = start
            .checked_add(granules(layout.size()))
            .filter(|&end| end <= self.cap)
            .ok_or(AllocError)?;
        self.top.set(end);
        let ptr = unsafe { self.block.add(start) };
        Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        if self.is_top(ptr, layout) {
            self.top.set(self.offset(ptr));
        }
    }

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        if self.is_top(ptr, old) && (ptr.as_ptr() as usize).is_multiple_of(new.align()) {
            let end = self
                .offset(ptr)
                .checked_add(granules(new.size()))
                .filter(|&end| end <= self.cap)
                .ok_or(AllocError)?;
            self.top.set(end);
            return Ok(NonNull::slice_from_raw_parts(ptr, new.size()));
        }
        let moved = self.allocate(new)?;
        unsafe {
            ptr.copy_to_nonoverlapping(moved.cast(), old.size());
            self.deallocate(ptr, old);
        }
        Ok(moved)
    }

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        let block = unsafe { self.grow(ptr, old, new)? };
        unsafe {
            block
                .cast::<u8>()
                .add(old.size())
                .write_bytes(0, new.size() - old.size());
        }
        Ok(block)
    }

    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        if !(ptr.as_ptr() as usize).is_multiple_of(new.align()) {
            let moved = self.allocate(new)?;
            unsafe {
                ptr.copy_to_nonoverlapping(moved.cast(), new.size());
                self.deallocate(ptr, old);
            }
            return Ok(moved);
        }
        if self.is_top(ptr, old) {
            self.top.set(self.offset(ptr) + granules(new.size()));
        }
        Ok(NonNull::slice_from_raw_parts(ptr, new.size()))
    }
}
```

## StackAllocator::{push,pop,push_all,pop_all}

Now, for the virtual machine spill stack interaction, pushing and popping is
necessary, for this i decided to implement these on the allocator itself,
noticeably these dont align up to 16, they instead align to T:

```rust
#[inline(always)]
pub fn push<T: Copy>(&self, value: T) -> bool {
    let top = self.top.get();
    debug_assert!(top.is_multiple_of(align_of::<T>()));
    let end = top + size_of::<T>();
    if std::hint::unlikely(end > self.cap) {
        return false;
    }
    unsafe { self.block.add(top).cast::<T>().write(value) };
    self.top.set(end);
    true
}

#[inline(always)]
pub unsafe fn pop<T: Copy>(&self) -> T {
    let top = self.top.get() - size_of::<T>();
    self.top.set(top);
    unsafe { self.block.add(top).cast::<T>().read() }
}

#[inline(always)]
pub fn push_all<T: Copy, const N: usize>(&self, values: [T; N]) -> bool {
    let top = self.top.get();
    debug_assert!(top.is_multiple_of(align_of::<T>()));
    let end = top + N * size_of::<T>();
    if std::hint::unlikely(end > self.cap) {
        return false;
    }
    let dst = unsafe { self.block.add(top).cast::<T>() };
    for (i, value) in values.into_iter().enumerate() {
        unsafe { dst.add(i).write(value) };
    }
    self.top.set(end);
    true
}

#[inline(always)]
pub unsafe fn pop_all<T: Copy, const N: usize>(&self) -> [T; N] {
    let top = self.top.get() - N * size_of::<T>();
    self.top.set(top);
    let src = unsafe { self.block.add(top).cast::<T>() };
    std::array::from_fn(|i| unsafe { src.add(i).read() })
}
```

# Now: Vm stack with actual stack space

So now given these helper methods I can replace the previous handlers with an
actual stack based spill stack, first allocating a stack buffer and creating
the allocator in `Vm::run`:

```rust
// 262144 B => 256KiB to spill results in /8 => 32768 vm values
pub const SPILL_STACK: usize = 256 << 10;

let mut spill_stack = [MaybeUninit::<u8>::uninit(); SPILL_STACK];
let spilled = StackAlloc::new(&mut spill_stack);
```

This is then used in all stack op code handlers:

```rust
Op::Push { src } => unsafe {
    if std::hint::unlikely(!spilled.push(*r!(src))) {
        return Err(Anomaly::StackOverflow { pc });
    }
},
Op::Push2 { a, b } => unsafe {
    if std::hint::unlikely(!spilled.push_all([*r!(a), *r!(b)])) {
        return Err(Anomaly::StackOverflow { pc });
    }
},
Op::Push3 { a, b, c } => unsafe {
    if std::hint::unlikely(!spilled.push_all([*r!(a), *r!(b), *r!(c)])) {
        return Err(Anomaly::StackOverflow { pc });
    }
},
Op::Pop { dst } => unsafe {
    r_mut!(dst) = spilled.pop::<Value>();
},
Op::Pop2 { a, b } => unsafe {
    let [below, top] = spilled.pop_all::<Value, 2>();
    r_mut!(a) = top;
    r_mut!(b) = below;
},
Op::Pop3 { a, b, c } => unsafe {
    let [bottom, below, top] = spilled.pop_all::<Value, 3>();
    r_mut!(a) = top;
    r_mut!(b) = below;
    r_mut!(c) = bottom;
},
```

# BENCHMARKS

For the commit
[1296116](https://github.com/xnacly/purple-garden/commit/12961166df8ebc66f26559e03fc8d13b3de4faa6)
this article is about, see
[bench/cross](https://github.com/xnacly/purple-garden/tree/master/bench/cross)
for the benchmark source code.

## Spill stack changes

> Benched on over 10 runs after 3 warmup runs, interpreter only (--no-jit),
> release builds with -C target-cpu=native on an AMD Ryzen 7 3700X. Before is
> the parent of commit 1296116, after is 1296116:

| bench         | before (ms) | after (ms) | speedup       |
| ------------- | ----------- | ---------- | ------------- |
| ackermann     | 162.9       | 129.1      | 1.26x / 20.8% |
| collatz       | 104.3       | 89.0       | 1.17x / 14.7% |
| fib           | 62.5        | 55.4       | 1.13x / 11.4% |
| gcd_sum       | 93.9        | 82.7       | 1.14x / 11.9% |
| keyword_table | 19.3        | 18.0       | 1.07x / 6.5%  |
| mandelbrot    | 73.4        | 60.7       | 1.21x / 17.4% |
| n_body        | 28.7        | 25.1       | 1.14x / 12.6% |
| primes_count  | 50.9        | 46.4       | 1.10x / 8.8%  |
| tak           | 322.5       | 267.5      | 1.21x / 17.0% |

So we are 6-20% faster for these benchmarks, thats a good results for such a
non invasive change :).

## VS with JIT enabled and against bun, luajit:

This is meant as a quick compare to how fast garden is when the jit is enabled
vs when the jit is disabled (see previous table). I removed python from this
table since it is so immensly slower than bun, luajit and garden:

> The jit doesnt yet support doubles, so it will be even quicker in the future O.O

I have cross language benchmarks available at
[xnacly.github.io/purple-garden/](https://xnacly.github.io/purple-garden/), the
table below is from commit [da1ad03](da1ad03dfd2b3f81ae1fa0472473a3c4927dc37f):

| workload      | garden (ms) | bun (ms) | luajit (ms) |       garden vs fastest |
| ------------- | ----------: | -------: | ----------: | ----------------------: |
| ackermann     |        39.3 |     40.8 |        39.8 |                 fastest |
| collatz       |        20.7 |     22.2 |        14.1 |  1.47x slower vs luajit |
| fib           |        17.9 |     16.1 |        9.61 |  1.86x slower vs luajit |
| gcd_sum       |        27.4 |     33.7 |        45.1 |                 fastest |
| keyword_table |        16.6 |      762 |        28.4 |                 fastest |
| mandelbrot    |        89.1 |     14.2 |        6.45 | 13.81x slower vs luajit |
| n_body        |        49.7 |     16.4 |        5.02 |  9.90x slower vs luajit |
| primes_count  |        7.96 |     17.7 |        6.09 |  1.31x slower vs luajit |
| tak           |        58.2 |     53.0 |        55.9 |     1.10x slower vs bun |

The website showing the results is embedded below (meaning this will update for
each new commit, they are measured with jit enabled though):

{{<rawhtml>}}
<iframe width="800px" height="400px" src="https://xnacly.github.io/purple-garden/"></iframe>
{{</rawhtml>}}
