---
title: "Porting a Segmented List From C to Rust"
summary: "Macros, Token pasting and Custom allocators vs Traits, `Option<Box<[MaybeUninit<T>]>>` and the borrow checker"
date: 2025-09-28
tags:
  - rust
  - c
draft: true
math: true
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

> This isn't a **_"C sucks because it's unsafe and Rust is super duper great
> because it borrow checks and it's safe"_** article, but rather a **_"I love C
> but lately I want to use Rust to help me get out of the pain of debugging my
> lexer, parser and compiler interacting with my segmented bump allocator
> backed by mmap, my handrolled generic segmented list and everything around
> that"_**.

## Segmented Lists vs Dynamic arrays

Vectors suck at growing a lot, because:

1. They have to allocate a new and larger block
2. They have to copy their contents to the new space
3. They require to "update" all references into the previous space to the new
   space
4. For large `mem::size_of::<T>()` / `sizeof(T)`, copies are costly and move a
   lot of memory

Segmented lists suck because:

1. The underlying storage is non-contiguous
2. Indexing requires addition, subtraction and bitshifts for finding the
   segment and its offset

The tradeoff is yours to make. In C benchmarks for large and many AST nodes,
segmented lists beat dynamic arrays by 2-4x.

### Design

### Indexing

Since a segmented list is based on a group of segments containing its elements,
indexing isn't as easy as incrementing a pointer by `sizeof(T)`. Instead we
have to compute the segment and the offset for any given index into the list
(\(i\)). Since a list starts with a default size (\(s_0\)) and grows at a
geometric rate (\(\lambda\)). We can compute the segment start with \(S(i)\),
the segment / block index with \(b(i)\) and the offset into said segment with
\(o(i)\):

$$
\begin{align}
S(b) &= s_0 \cdot (\lambda^{b} - 1) \\
b(i) &= \left\lfloor \log_{\lambda} \left( \frac{i}{s_0} + 1 \right) \right\rfloor \\
o(i) &= i - S(b(i))
\end{align}
$$

Therefore, for our segmented list, given \(s_o := 8\), \(\lambda := 2\) and an
index \(i := 18\), we can calculate:

$$
\begin{align}
b(i) &= \left\lfloor \log_{\lambda} \left( \frac{i}{s_0} + 1 \right) \right\rfloor \\
b(18)&= \left\lfloor \log_{2} \left( \frac{18}{8} + 1 \right) \right\rfloor \\
     &= \left\lfloor \log_{2} \left( 3.25 \right) \right\rfloor \\
     &= \left\lfloor 1.7004 \right\rfloor \\
     &= \underline{1} \\
S(b) &= s_0 \cdot (\lambda^{b} - 1) \\
S(1) &= 8 \cdot (2^{1} - 1) \\
     &= \underline{8} \\
o(i) &= i - S(b(i)) \\
o(18)&= 18 - 8 \\
     &= \underline{10} \\
\end{align}
$$

Thus, attempting to index at the position \(18\) requires us to access the
segment at position \(1\) with its inner offset of \(10\).

## C Implementation

This is my starting point I whipped up in an afternoon. Please keep in mind:
this is my first allocator in any sense, I'm still fiddeling around and thusfar
asan, valgrind, gcc, clang and my unittests tell me this is fine.

### Bump allocator

In purple garden all allocators are based on the `Allocator` "interface" to
allow for dynamically replacing the bump allocator with different other
allocators, for instance garbage collectors.

```c
// mem.h
typedef struct {
  size_t current;
  size_t allocated;
} Stats;

// CALL is used to emulate method calls by calling a METHOD on SELF with
// SELF->ctx and __VA_ARGS__, this is useful for interface interaction, such as
// Allocator, which reduces alloc_bump.request(alloc_bump.ctx, 64); to
// CALL(alloc_bump, request, 64), removing the need for passing the context in
// manually
#ifdef VERBOSE_ALLOCATOR
#include <stdio.h>
#define CALL(SELF, METHOD, ...)                                                \
  (fprintf(stderr, "[ALLOCATOR] %s@%s::%d: %s->%s(%s)\n", __FILE__, __func__,  \
           __LINE__, #SELF, #METHOD, #__VA_ARGS__),                            \
   (SELF)->METHOD((SELF)->ctx, ##__VA_ARGS__))
#else
#define CALL(SELF, METHOD, ...) (SELF)->METHOD((SELF)->ctx, ##__VA_ARGS__)
#endif

// Allocator defines an interface abstracting different allocators, so the
// runtime of the virtual machine does not need to know about implementation
// details, can be used like this:
//
//
//  #define ALLOC_HEAP_SIZE = 1024
//  Allocator alloc_bump = bump_init(ALLOC_HEAP_SIZE, ALLOC_HEAP_SIZE*2);
//
//  size_t some_block_size = 16;
//  void *some_block = alloc_bump.request(alloc_bump.ctx, some_block_size);
//
//  alloc_bump.destroy(alloc_bump.ctx);
//
typedef struct {
  // Allocator::ctx refers to an internal allocator state and owned memory
  // areas, for instance, a bump allocator would attach its meta data (current
  // position, cap, etc) here
  void *ctx;

  // Allocator::stats is expected to return the current statistics of the
  // underlying allocator
  Stats (*stats)(void *ctx);
  // Allocator::request returns a handle to a block of memory of size `size`
  void *(*request)(void *ctx, size_t size);
  // Allocator::destroy cleans state up and deallocates any owned memory areas
  void (*destroy)(void *ctx);
} Allocator;

Allocator *bump_init(uint64_t min_size, uint64_t max_size);
```

The segmented bump allocator itself is of course pretty simple, allocate page
aligned block, hand out memory by incrementing the pointer, if out of space in
the current block, allocate the next one, as shown for the first three blocks
below:

![first three block sizes](/segmented-list/block-sizes.png)

```c
#define _GNU_SOURCE
#include "common.h"
#include "mem.h"
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define BUMP_MIN_START 4096
// geometric series result for max amount of bytes fitting into uint64_t used to
// count the totally allocated bytes; amounts to something like (2^64)-
#define BUMP_MAX_BLOCKS 55
#define BUMP_GROWTH 2

// BumpResize allocator header
//
// The bump allocator is implemented as such, so a "regrow" (needing the next
// block) doesnt invalidate all previously handed out pointers. ALWAYS zero all
// handed out memory yourself
typedef struct {
  // the current block we are in, max is BUMP_MAX_BLOCKS
  uint64_t pos;

  // the size of the current allocated block
  uint64_t size;

  // the amount of bytes in the current block in use
  uint64_t len;

  // the max amount the bump alloc should grow to
  uint64_t max;

  // kept for Allocator->stats
  uint64_t total_used;
  uint64_t total_allocated;

  // List of blocks the bump allocator uses to hand out memory
  void *blocks[BUMP_MAX_BLOCKS];
  uint64_t block_sizes[BUMP_MAX_BLOCKS];
} BumpCtx;

void *bump_request(void *ctx, size_t size) {
  BumpCtx *b_ctx = ctx;
  size_t align = sizeof(void *);
  uint64_t aligned_pos = (b_ctx->len + align - 1) & ~(align - 1);

  if (b_ctx->max > 0) {
    ASSERT(b_ctx->total_allocated < b_ctx->max,
           "Bump allocator exceeded max_size");
  }

  if (aligned_pos + size > b_ctx->size) {
    ASSERT(b_ctx->pos + 1 < BUMP_MAX_BLOCKS, "Out of block size");
    uint64_t new_size = b_ctx->size * BUMP_GROWTH;

    void *new_block = mmap(NULL, new_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(new_block != MAP_FAILED, "Failed to mmap new block");

    b_ctx->blocks[++b_ctx->pos] = new_block;
    b_ctx->block_sizes[b_ctx->pos] = new_size;
    b_ctx->size = new_size;
    b_ctx->len = 0;
    aligned_pos = 0;
    b_ctx->total_allocated += new_size;
  }

  void *ptr = (char *)b_ctx->blocks[b_ctx->pos] + aligned_pos;
  b_ctx->total_used += (aligned_pos - b_ctx->len) + size;
  b_ctx->len = aligned_pos + size;
  return ptr;
}

Allocator *bump_init(uint64_t min_size, uint64_t max_size) {
  BumpCtx *ctx = malloc(sizeof(BumpCtx));
  ASSERT(ctx != NULL, "failed to bump allocator context");
  *ctx = (BumpCtx){0};
  ctx->size = min_size < BUMP_MIN_START ? BUMP_MIN_START : min_size;
  ctx->max = max_size;
  void *first_block = mmap(NULL, ctx->size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT(first_block != MAP_FAILED, "Failed to mmap initial block");
  ctx->blocks[0] = first_block;
  ctx->total_allocated = ctx->size;

  Allocator *a = malloc(sizeof(Allocator));
  ASSERT(a != NULL, "failed to alloc bump allocator");
  *a = (Allocator){0};
  a->ctx = (void *)ctx;
  a->destroy = bump_destroy;
  a->request = bump_request;
  a->stats = bump_stats;

  return a;
}
```

Deallocation is done by unmapping each allocated block.

```c
void bump_destroy(void *ctx) {
  ASSERT(ctx != NULL, "bump_destroy on already destroyed allocator");
  BumpCtx *b_ctx = (BumpCtx *)ctx;
  for (size_t i = 0; i <= b_ctx->pos; i++) {
    if (b_ctx->blocks[i]) {
      munmap(b_ctx->blocks[i], b_ctx->block_sizes[i]);
      b_ctx->blocks[i] = NULL;
    }
  }
  free(ctx);
}
```

With the interface and this implementation all functions in the purple garden
code base that allocate take `Allocator *a` (or `Allocator *alloc`) and
requests memory with `CALL(a, request, 1024)`. For instance in the virtual
machine when creating a new space for the globals:

```c
vm.globals = CALL(alloc, request, (sizeof(Value) * GLOBAL_SIZE));
```

### List macros and C "Generics"

My first step was to make use of the macro system to create a "generic" container:

```text
#include "mem.h"
#include "strings.h"
#include <string.h>

#define LIST_DEFAULT_SIZE 8
#define LIST_BLOCK_COUNT 24

#define LIST_TYPE(TYPE)                                                        \
  typedef struct {                                                             \
    TYPE **blocks;                                                             \
    uint64_t len;                                                              \
    size_t type_size;                                                          \
  } LIST_##TYPE

#define LIST_new(TYPE)                                                         \
  ({                                                                           \
    LIST_##TYPE l = {0};                                                       \
    l.type_size = sizeof(TYPE);                                                \
    l;                                                                         \
  })
```

These macros are then used to define and create a list via:

```c
LIST_TYPE(char) cl = LIST_new(char);
```

Now there is the need for interacting with the list, for this we need append,
get and insert (plus their non bounds checking equivalents), allowing for:

```c
Allocator *a = bump_init(1024);
LIST_TYPE(char) cl = LIST_new(char);
LIST_append(&cl, a, 'H')
LIST_append(&cl, a, 'E')
LIST_append(&cl, a, 'L')
assert(LIST_get(&cl, 0) == 'H')
assert(LIST_get(&cl, 1) == 'E')
assert(LIST_get(&cl, 2) == 'L')
assert(LIST_insert_UNSAFE(&cl, 1, 'O'))
assert(LIST_get_UNSAFE(&cl, 1) == 'O')
```

All of these macros require the index into the block and the block itself.
`ListIdx` and `idx_to_block_idx` do exactly that:

```c
struct ListIdx {
  // which block to use for the indexing
  uint64_t block;
  // the idx into said block
  uint64_t block_idx;
};

struct ListIdx idx_to_block_idx(size_t idx);
```

The implementation of `idx_to_block_idx` works in constant time and is
therefore a bit worse to read than one working in linear time due to the
exploitation of the geometric series, it does however follow
[Indexing](#indexing), just with a few changes to omit heavy computations
(\(\log_2\), etc.).

```c
struct ListIdx idx_to_block_idx(size_t idx) {
  struct ListIdx r = {0};
  if (idx < LIST_DEFAULT_SIZE) {
    r.block_idx = idx;
    return r;
  }

  // This optimizes the block index lookup to be constant time
  //
  //     block 0 size = LIST_DEFAULT_SIZE
  //     block 1 size = LIST_DEFAULT_SIZE*2
  //     block 2 size = LIST_DEFAULT_SIZE*4
  //     block 3 size = LIST_DEFAULT_SIZE*8
  //
  // The starting index of each block is a geometric series:
  //
  //    s(i) = LIST_DEFAULT_SIZE * (2^i - 1)
  //
  // We solve for i, so the following stands:
  //
  //    s(i) <= idx < s(i+1)
  //
  //    2^i - 1 <= idx / LIST_DEFAULT_SIZE < 2^(i+1) - 1
  //    idx / LIST_DEFAULT_SIZE + 1 >= 2^i
  //
  // Thus: adding LIST_DEFAULT_SIZE to idx shifts the series so the msb of idx +
  // LIST_DEFAULT_SIZE correspond to the block number
  //
  // Visually:
  //
  //     Global index:  0 1 2 3 4 5 6 7  |  8  9 10 ... 23  | 24 25 ... 55  | 56
  //     ... Block:     0                |  1               |  2            | 3
  //     Block size:    8                | 16               | 32            | 64
  //     ... idx + LIST_DEFAULT_SIZE: 0+8=8  -> MSB pos 3 -> block 0 7+8=15 ->
  //     MSB pos 3 -> block 0 8+8=16 -> MSB pos 4 -> block 1 23+8=31-> MSB pos 4
  //     -> block 1 24+8=32-> MSB pos 5 -> block 2

  // shifting the geometric series so 2^i aligns with idx
  uint64_t adjusted = idx + LIST_DEFAULT_SIZE;
  uint64_t msb_pos = 63 - __builtin_clzll(adjusted);

  //   log2(LIST_DEFAULT_SIZE) = 3 for LIST_DEFAULT_SIZE = 8
#define LOG2_OF_LIST_DEFAULT_SIZE 3
  // first block is LIST_DEFAULT_SIZE wide, this normalizes
  r.block = msb_pos - LOG2_OF_LIST_DEFAULT_SIZE;

  uint64_t start_index_of_block = LIST_DEFAULT_SIZE * ((1UL << r.block) - 1);
  r.block_idx = idx - start_index_of_block;
  return r;
}
```

`LIST_append` allocates on demand, based on the segment computed by
`idx_to_block_idx`:

```text
#define LIST_append(LIST, ALLOC, ELEM)                                         \
  {                                                                            \
    /* allocate block array if not yet allocated */                            \
    if ((LIST)->blocks == NULL) {                                              \
      (LIST)->blocks =                                                         \
          CALL(ALLOC, request, LIST_BLOCK_COUNT * sizeof(void *));             \
      ASSERT((LIST)->blocks != NULL,                                           \
             "LIST_append: block array allocation failed");                    \
    }                                                                          \
                                                                               \
    struct ListIdx bi = idx_to_block_idx((LIST)->len);                         \
                                                                               \
    /* allocate the specific block if needed */                                \
    if ((LIST)->blocks[bi.block] == NULL) {                                    \
      uint64_t block_size = LIST_DEFAULT_SIZE << bi.block;                     \
      (LIST)->blocks[bi.block] =                                               \
          CALL(ALLOC, request, block_size * (LIST)->type_size);                \
      ASSERT((LIST)->blocks[bi.block] != NULL,                                 \
             "LIST_append: block allocation failed");                          \
    }                                                                          \
                                                                               \
    (LIST)->blocks[bi.block][bi.block_idx] = (ELEM);                           \
    (LIST)->len++;                                                             \
  }
```

The non allocating interactions like `_get`, `_get_UNSAFE` and `_insert_UNSAFE`
do a bounds check if applicable and afterwards use the segment and the offset
computed by `idx_to_block_idx`:

```text
#define LIST_get(LIST, IDX)                                                    \
  ({                                                                           \
    ASSERT(IDX < (LIST)->len, "List_get out of bounds");                       \
    struct ListIdx b_idx = idx_to_block_idx(IDX);                              \
    (LIST)->blocks[b_idx.block][b_idx.block_idx];                              \
  })

#define LIST_get_UNSAFE(LIST, IDX)                                             \
  ({                                                                           \
    struct ListIdx b_idx = idx_to_block_idx(IDX);                              \
    (LIST)->blocks[b_idx.block][b_idx.block_idx];                              \
  })

#define LIST_insert_UNSAFE(LIST, IDX, VAL)                                     \
  {                                                                            \
    struct ListIdx __idx = idx_to_block_idx(IDX);                              \
    (LIST)->blocks[__idx.block][__idx.block_idx] = VAL;                        \
  }
```

## Rust Implementation

> _"If you wish to make an apple pie from scratch, you must first invent the universe."_
>
> -Carl Sagan

In this fashion we will:

1. Implement mmap and munmap in assembly using the x86 Linux syscall ABI
2. Implement a `std::alloc::GlobalAlloc` compatible allocator based on that
3. Implement the segmented list using the allocator
4. Profit.

### Handrolling x86 mmap & munmap syscalls

About using the `libc` crate: This would be against my mentality of not using
dependencies if possible and libc is a large one due to it pulling in the C
runtime for two syscalls I can just wrap myself using
[`asm!`](https://doc.rust-lang.org/reference/inline-assembly.html).

> Of course the above is only correct on Linux `#[no_std]` since in some cases
> Rusts std depends on libc, but you get what I'm trying to convey.

My first step was porting their arguments into the Rust type system. I couldn't
use rust enums, since they require variants to be exclusive, which the bit
flags for `READ`, `WRITE`, ... and `PRIVATE`, `ANONYMOUS`, ... aren't. So i had
to settle for a struct containing `i32`. To support bit or(ed) flags for the
arguments I also had to quickly implement `std::ops::BitOr`:

```rust
//! constants taken from https://github.com/openbsd/src/blob/master/sys/sys/mman.h
#[cfg(target_os = "openbsd")]
const MMAP_SYSCALL: i64 = 197;
#[cfg(target_os = "openbsd")]
const MUNMAP_SYSCALL: i64 = 73;

#[cfg(target_os = "linux")]
const MMAP_SYSCALL: i64 = 9;
#[cfg(target_os = "linux")]
const MUNMAP_SYSCALL: i64 = 11;

// Not an enum, since NONE, READ, WRITE and EXEC aren't mutually exclusive
pub struct MmapProt(i32);
impl MmapProt {
    /// no permissions
    pub const NONE: MmapProt = MmapProt(0x00);
    /// pages can be read
    pub const READ: MmapProt = MmapProt(0x01);
    /// pages can be written
    pub const WRITE: MmapProt = MmapProt(0x02);
    /// pages can be executed
    pub const EXEC: MmapProt = MmapProt(0x04);
    pub fn bits(self) -> i32 {
        self.0
    }
}

impl std::ops::BitOr for MmapProt {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        MmapProt(self.0 | rhs.0)
    }
}

pub struct MmapFlags(i32);

impl MmapFlags {
    /// share changes
    pub const SHARED: MmapFlags = MmapFlags(0x0001);
    /// changes are private
    pub const PRIVATE: MmapFlags = MmapFlags(0x0002);
    /// map addr must be exactly as requested
    pub const FIXED: MmapFlags = MmapFlags(0x0010);

    /// fail if address not available
    #[cfg(target_os = "openbsd")]
    pub const NOREPLACE: MmapFlags = MmapFlags(0x0800); // __MAP_NOREPLACE
    #[cfg(target_os = "linux")]
    pub const NOREPLACE: MmapFlags = MmapFlags(0x100000); // MAP_FIXED_NOREPLACE (Linux ≥ 5.4)

    /// allocated from memory, swap space
    #[cfg(target_os = "openbsd")]
    pub const ANONYMOUS: MmapFlags = MmapFlags(0x1000);
    /// allocated from memory, swap space
    #[cfg(target_os = "linux")]
    pub const ANONYMOUS: MmapFlags = MmapFlags(0x20);

    /// mapping is used for stack
    pub const STACK: MmapFlags = MmapFlags(0x4000);

    /// omit from dumps
    pub const CONCEAL: MmapFlags = MmapFlags(0x8000);

    // OpenBSD-only: avoid faulting in pages initially
    #[cfg(target_os = "openbsd")]
    pub const NOFAULT: MmapFlags = MmapFlags(0x2000);
    pub fn bits(self) -> i32 {
        self.0
    }
}
```

The functions themselves are pretty straightforward if you have ever called a
syscall from assembly. We use the `syscall` instruction and fill some registers
with the arguments according to the [x86 Linux syscall
ABI](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI):

| Registers | Value                                                         |
| --------- | ------------------------------------------------------------- |
| `rax`     | Syscall kind (`9` for `mmap`)                                 |
| `rdi`     | pointer or null for anonymous (`Option::None` for the latter) |
| `rsi`     | region length                                                 |
| `rdx`     | protection modifiers                                          |
| `r10`     | flags                                                         |
| `r8`      | file descriptor (`-1` for anonymous)                          |
| `r9`      | offset                                                        |

The only thing tripping me up were the possible values for `options` and
`lateout`, since these weren't obvious to me. After a lot of searching I found
some
[docs](https://doc.rust-lang.org/reference/inline-assembly.html#r-asm.options):

| Option    | Dacription                                              |
| --------- | ------------------------------------------------------- |
| `nostack` | asm does not modify the stack via push, pop or red-zone |

[`lateout`](https://doc.rust-lang.org/reference/inline-assembly.html#r-asm.operand-type.supported-operands.lateout)
writes the register contents to its argument and doesn't care about overwriting
inputs. The `std::ptr::NonNull` return type is applicable, since mmap can only
return valid non-null memory, otherwise the `rax` would return `MMAP_FAILED`
(`(void *) -1` in Rust simply `-1`). I only use `nostack`, since we don't
fiddle with the stack. Other options like `readonly` or `preserves_flags`
aren't applicable, since `syscall` writes to `rax` and modifies `RFLAGS`

```rust
#[inline(always)]
pub fn mmap(
    ptr: Option<std::ptr::NonNull<u8>>,
    length: usize,
    prot: MmapProt,
    flags: MmapFlags,
    fd: i32,
    offset: i64,
) -> std::ptr::NonNull<u8> {
    let ret: isize;

    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") MMAP_SYSCALL,
            in("rdi") ptr.map(|nn| nn.as_ptr()).unwrap_or(std::ptr::null_mut()),
            in("rsi") length,
            in("rdx") prot.bits(),
            in("r10") flags.bits(),
            in("r8")  fd,
            in("r9")  offset,
            lateout("rax") ret,
            clobber_abi("sysv64"),
            options(nostack)
        );
    }
    if ret < 0 {
        let errno = -ret;
        eprintln!(
            "mmap failed (errno {}): {}",
            errno,
            std::io::Error::from_raw_os_error(errno as i32)
        );
        std::process::abort()
    }

    unsafe { std::ptr::NonNull::new_unchecked(ret as *mut u8) }
}
```

Unmapping is easier than `mmap`, since it only requires a pointer to the mapped
region in `rdi` and its size in `rsi`. We again use `rax` to check if the
kernel complained about our syscall parameters.

```rust
#[inline(always)]
pub fn munmap(ptr: std::ptr::NonNull<u8>, size: usize) {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") MUNMAP_SYSCALL,
            in("rdi") ptr.as_ptr(),
            in("rsi") size,
            lateout("rax") ret,
            clobber_abi("sysv64"),
            options(nostack)
        );
    }

    if ret < 0 {
        let errno = -ret;
        eprintln!(
            "munmap failed (errno {}): {}",
            errno,
            std::io::Error::from_raw_os_error(errno as i32)
        );
        std::process::abort()
    }
}
```

### Bump allocator

The bump allocator now uses these safe syscall wrappers to allocate and
deallocate memory chunks, it also implements `std::alloc::GlobalAlloc` and
therefore also has to implement `Send` and `Sync`.

The main component of the allocator is its metadata - `SegmentedAllocCtx`:

```rust
const MIN_SIZE: usize = 4096;
const MAX_BLOCKS: usize = 55;
const GROWTH: usize = 2;

#[derive(Debug)]
struct SegmentedAllocCtx {
    /// idx into self.blocks
    cur_block: usize,
    /// size of the current block
    size: usize,
    /// bytes in use of the current block
    pos: usize,
    blocks: [Option<NonNull<u8>>; MAX_BLOCKS],
    block_sizes: [usize; MAX_BLOCKS],
}

impl SegmentedAllocCtx {
    const fn new() -> Self {
        SegmentedAllocCtx {
            size: MIN_SIZE,
            cur_block: 0,
            pos: 0,
            blocks: [const { None }; MAX_BLOCKS],
            block_sizes: [0; MAX_BLOCKS],
        }
    }
}
```

Since I don't care about thread safety and this is just a comparison between my
already thread unsafe C code, this context is wrapped in an `UnsafeCell`:

```rust
/// Implements a variable size bump allocator, employing mmap to allocate a starting block of
/// 4096B, once a block is exceeded by a request, the allocator mmaps a new block double the size
/// of the previously allocated block
pub struct SegmentedAlloc {
    ctx: UnsafeCell<SegmentedAllocCtx>,
}
```

To cement this unsafeness, `Sync` and `Send` are implemented as nops, this also
requires never using `SegmentedAlloc` in multithreaded contexts.

```rust
unsafe impl Send for SegmentedAlloc {}
unsafe impl Sync for SegmentedAlloc {}
```

I ported the bump allocator line by line to rust:

```rust
#[inline(always)]
fn align_up(val: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (val + align - 1) & !(align - 1)
}

impl SegmentedAlloc {
    pub const fn new() -> Self {
        Self {
            ctx: UnsafeCell::new(SegmentedAllocCtx::new()),
        }
    }

    pub fn request(&self, layout: std::alloc::Layout) -> NonNull<u8> {
        assert!(layout.size() > 0, "Zero-size allocation is not allowed");
        assert!(
            layout.align().is_power_of_two(),
            "Alignment must be power-of-two per GlobalAlloc contract"
        );

        let ctx = unsafe { &mut *self.ctx.get() };

        if ctx.blocks[0].is_none() {
            ctx.size = MIN_SIZE;
            ctx.cur_block = 0;
            ctx.pos = 0;
            ctx.block_sizes[0] = MIN_SIZE;
            ctx.blocks[0] = Some(mmap(
                None,
                MIN_SIZE,
                mmap::MmapProt::READ | mmap::MmapProt::WRITE,
                mmap::MmapFlags::PRIVATE | mmap::MmapFlags::ANONYMOUS,
                -1,
                0,
            ));
        }

        loop {
            let block_capacity = ctx.block_sizes[ctx.cur_block];
            debug_assert!(
                block_capacity >= ctx.size,
                "block_capacity should be >= ctx.size"
            );

            let offset = align_up(ctx.pos, layout.align());
            let end_offset = offset
                .checked_add(layout.size())
                .expect("Allocation size overflow");

            if end_offset >= block_capacity {
                assert!(ctx.cur_block + 1 < MAX_BLOCKS, "Exceeded MAX_BLOCKS");
                let new_size = ctx.size * GROWTH;
                ctx.cur_block += 1;
                ctx.block_sizes[ctx.cur_block] = new_size;
                ctx.size = new_size;
                ctx.pos = 0;
                ctx.blocks[ctx.cur_block] = Some(mmap(
                    None,
                    new_size,
                    mmap::MmapProt::READ | mmap::MmapProt::WRITE,
                    mmap::MmapFlags::PRIVATE | mmap::MmapFlags::ANONYMOUS,
                    -1,
                    0,
                ));
                continue;
            }

            let block_ptr = ctx.blocks[ctx.cur_block].unwrap();

            let ptr_addr = unsafe { block_ptr.as_ptr().add(offset) };
            debug_assert!(
                (ptr_addr as usize) % layout.align() == 0,
                "Returned pointer is not aligned to {}",
                layout.align()
            );

            ctx.pos = end_offset;

            return NonNull::new(ptr_addr)
                .expect("Failed to create NonNull from allocation pointer");
        }
    }

    pub fn free(&mut self) {
        let ctx = unsafe { &mut *self.ctx.get() };
        for i in 0..MAX_BLOCKS {
            let size = ctx.block_sizes[i];
            if size == 0 {
                break;
            }

            let Some(block) = ctx.blocks[i] else {
                break;
            };
            munmap(block, size);
        }
    }
}
```

### Rudimentary Bump Allocator Tests


### Segmented List

### Optimisations

<!-- TODO: provide context for these -->

- Inline `alloc_block`, `idx_to_block_idx` (-2%)
- Inline `mmap` and `munmap` (-4%)
- precompute block boundaries in `BLOCK_STARTS` (-41%)
- remove unnecessary indirections (-8%)

## Runtime and Memory Comparison of C, Rust and std::vec::Vec

### Rust Benchmark setup

## Pain points

- Sync and Send have to be implemented for `std::alloc::GlobalAlloc`
- Tests are concurrent and therefore crash if not run with `--test-threads=1`
- Segfaults in Rust are worse to debug with `gdb` than in C
- No stack traces for `panic!` when implementing `std::alloc::GlobalAlloc`, just:
  ```text
  panic:
  ```
