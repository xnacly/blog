---
title: "Porting a Segmented List From C to Rust"
summary: "Macros, Token pasting and Custom allocators vs Traits, `Option<Box<[MaybeUninit<T>]>>` and the borrow checker"
date: 2025-10-16
tags:
  - rust
  - C
math: true
---

{{<callout type="TLDR: Info">}}
Porting a segmented list from C to Rust and sharing the process. Both written
from scratch and without any dependencies:

```c
Allocator *a = bump_init(1024, 0);
LIST_TYPE(size_t);
LIST_size_t list = LIST_new(size_t);
size_t count = 64 * 1000 * 1000;
for (size_t i = 0; i < count; i++) {
    LIST_append(&list, a, i);
}
ASSERT(list.len == count, "list not of correct length");
CALL(a, destroy);
free(a);
```

to

```rust
let mut list = SegmentedList::new();
let count = 64 * 1000 * 1000;
for i in 0..count {
    list.push(i);
}
assert_eq!(list.len(), count);
```

{{</callout>}}

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

# Segmented Lists vs Dynamic Arrays

Vectors suck at growing a lot, because:

1. They have to allocate a new and larger block
2. They have to copy their contents to the new space
3. They require to "update" all references into the previous space to the new
   space
4. For large `mem::size_of::<T>()` / `sizeof(T)`, copies are costly and move a
   lot of memory

On the other hand, segmented lists suck due to:

1. The underlying storage being non-contiguous
2. Indexing requiring addition, subtraction and bitshifts for finding the
   segment and its offset

The tradeoff is yours to make. In C benchmarks for large and many AST nodes,
segmented lists beat dynamic arrays by 2-4x.

## Design

As the name implies, the list consists of segments. Each segment's size is that
of its predecessor multiplied by an implementation-defined growth factor, often
1.5 or 2, this results in geometric growth, reducing the amount of syscalls
while growing progressively larger.


The first segment size is also implementation-defined, but often chosen to be
8, a multiple of 2 is, as always, favorable for aligned access and storage.
Segments are lazily allocated when they are about to be used. There is no
deallocation per element, but rather per segment, at least in this example. The
main upside of segmented lists is their zero-copy growth. Other dynamic array
implementations often require the previously stored elements to be moved, thus
also providing stable pointers.

## Indexing

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

Therefore, for our segmented list, given \(s_0 := 8\), \(\lambda := 2\) (I use
2, since geometric growth means less syscalls for fast growing lists, the
equations hold for \(\lambda > 1\)) and an index \(i := 18\), we can
calculate:

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

# C Implementation

This is my starting point I whipped up in an afternoon. Please keep in mind:
this is my first allocator in any sense, I'm still fiddeling around and thusfar
asan, valgrind, gcc, clang and my unittests tell me this is fine.

## Bump allocator

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

## List macros and C "Generics"

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
    size_t len;                                                              \
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
Allocator *a = bump_init(1024, 0);
LIST_TYPE(char);
LIST_char cl = LIST_new(char);
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
  size_t block;
  // the idx into said block
  size_t block_idx;
};

struct ListIdx idx_to_block_idx(size_t idx);
```

The implementation of `idx_to_block_idx` works in constant time and is
therefore a bit worse to read than one working in linear time due to the
exploitation of the geometric series, it does however follow
[Indexing](#indexing), just with a few changes to omit heavy computations
(\(\log_2\), etc.).

```c
inline __attribute__((always_inline, hot)) struct ListIdx idx_to_block_idx(size_t idx) {
  if (idx < LIST_DEFAULT_SIZE) {
    return (struct ListIdx){.block_idx = idx, .block = 0};
  }

  size_t adjusted = idx + LIST_DEFAULT_SIZE;
  size_t msb_pos = 63 - __builtin_clzll(adjusted);

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
  //     ... Block:         0                 |  1              |  2 | 3 ...
  //     Block size:    8                 | 16              | 32            | 64
  //     ... idx + LIST_DEFAULT_SIZE: 0+8=8  -> MSB pos 3 -> block 0 7+8=15 ->
  //     MSB pos 3 -> block 0 8+8=16 -> MSB pos 4 -> block 1 23+8=31-> MSB pos 4
  //     -> block 1 24+8=32-> MSB pos 5 -> block 2

  // shifting the geometric series so 2^i aligns with idx

  //   log2(LIST_DEFAULT_SIZE) = 3 for LIST_DEFAULT_SIZE = 8
#define LOG2_OF_LIST_DEFAULT_SIZE 3
  // first block is LIST_DEFAULT_SIZE wide, this normalizes
  size_t block = msb_pos - LOG2_OF_LIST_DEFAULT_SIZE;
  size_t start_index_of_block =
      (LIST_DEFAULT_SIZE << block) - LIST_DEFAULT_SIZE;
  size_t block_idx = idx - start_index_of_block;

  return (struct ListIdx){.block_idx = block_idx, .block = block};
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

# Rust Implementation

> _"If you wish to make an apple pie from scratch, you must first invent the universe."_
>
> -Carl Sagan

In this fashion we will:

1. Implement mmap and munmap in assembly using the x86 Linux syscall ABI
2. Implement a `std::alloc::GlobalAlloc` compatible allocator based on that
3. Implement the segmented list using the allocator
4. Profit.

## Handrolling x86 mmap & munmap syscalls

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

## Bump allocator

The bump allocator now uses these safe syscall wrappers to allocate and
deallocate memory chunks, it also implements `std::alloc::GlobalAlloc` and
needs to implement `Send` and `Sync` since its used via `#[global_allocator]`,
which is static and requires the corresponding traits.

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

I ported the bump allocator line by line to rust. It uses the `mmap` and
`munmap` wrappers, keeps track of its state via `SegmentedAllocCtx` and hands
out data via `SegmentedAlloc::request`. `SegmentedAlloc::free` is the basis for
implementing `Drop` for `SegmentedList` which will come in the next section.

```rust
#[inline(always)]
fn align_up(val: usize, align: usize) -> usize {
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

`std::alloc::GlobalAlloc` is just an abstraction to calling
`SegmentedAlloc::request` on alloc and nop on dealloc:

```rust
unsafe impl GlobalAlloc for SegmentedAlloc {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        self.request(layout).as_ptr()
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: std::alloc::Layout) {}
}
```

We can now use the following to make our complete program use the allocator:

```rust
use segmented_rs::alloc;

#[global_allocator]
static A: alloc::SegmentedAlloc = alloc::SegmentedAlloc::new();
```

Or we inject the allocator into our list to only make it use the allocator.

## Segmented List

As introduced in [Segmented Lists vs Dynamic
Arrays](#segmented-lists-vs-dynamic-arrays), a segmented list consists of
segments. Each segment is lazily allocated and doubles in size to the previous
one. The first segment is of size `8`, the next `16`, the next `32`, and so on.
Keeping track of these sizes and the starting point is crucial for indexing.

```rust
// 24 blocks means around 134mio elements, thats enough I think
pub const BLOCK_COUNT: usize = 24;
pub const START_SIZE: usize = 8;
pub const BLOCK_STARTS: [usize; BLOCK_COUNT] = {
    let mut arr = [0usize; BLOCK_COUNT];
    let mut i = 0;
    while i < BLOCK_COUNT {
        arr[i] = START_SIZE * ((1 << i) - 1);
        i += 1;
    }
    arr
};

/// SegmentedIdx represents a cached index lookup into the segmented list, computed with
/// `SegmentedList::compute_segmented_idx`, can be used with `SegmentedList::get_with_segmented_idx`
/// and `SegmentedList::get_mut_with_segmented_idx`.
///
/// Primary usecase is to cache the lookup of many idxes, thus omiting the lookup computation which
/// can be too heavy in intensive workloads.
#[derive(Copy, Clone)]
struct SegmentedIdx(usize, usize);

/// SegmentedList is a drop in `std::vec::Vec` replacement providing zero cost growing and stable
/// pointers even after grow with `::push`.
///
/// The list is implemented by chaining blocks of memory to store its elements. Each block is
/// allocated on demand when an index falls into it (for instance during appends), starting at
/// `START_SIZE` elements in the first block and doubling the block size for each subsequent
/// allocation. This continues until `BLOCK_COUNT` is reached. Existing blocks are never moved or
/// reallocated, so references into the list remain valid across growth operations.
///
/// This makes the SegmentedList an adequate replacement for `std::vec::Vec` when dealing with
/// heavy and unpredictable growth workloads due the omission of copy/move overhead on expansion.
pub struct SegmentedList<T> {
    blocks: [*mut std::mem::MaybeUninit<T>; BLOCK_COUNT],
    block_lengths: [usize; BLOCK_COUNT],
    allocator: SegmentedAlloc,
    cur_block: usize,
    offset_in_block: usize,
    len: usize,
}
```

`SegmentedList` holds an array of segments (`blocks`), an array of their
lengths (`block_lengths`), the allocator used to do any allocation and the
count of the currently contained elements, overarching all segments - `len`.

The main logic for indexing is encoded in the `SegmentedIdx(segment, offset)`
struct and its producer: `idx_to_block_idx`.

```rust
impl <T> SegmentedList<T> {

    // [...]

    #[inline(always)]
    fn idx_to_block_idx(&self, idx: usize) -> SegmentedIdx {
        if idx < START_SIZE {
            return SegmentedIdx(0, idx);
        }
        let adjusted = idx + START_SIZE;
        let msb_pos = core::mem::size_of::<usize>() * 8 - 1 - adjusted.leading_zeros() as usize;
        let block = msb_pos - (START_SIZE.trailing_zeros() as usize);
        SegmentedIdx(block, idx - BLOCK_STARTS[block])
    }

    // [...]

}
```

In comparison to the C implementation, the Rust one doesnt lazy allocate the
first chunk, but eagerly allocates its first segment in `Self::new` (I don't
remember why I did that):

```rust
impl <T> SegmentedList<T> {
    pub fn new() -> Self {
        let mut s = Self {
            blocks: [std::ptr::null_mut(); BLOCK_COUNT],
            block_lengths: [0; BLOCK_COUNT],
            allocator: SegmentedAlloc::new(),
            cur_block: 0,
            len: 0,
            offset_in_block: 0,
        };

        let element_count = START_SIZE;
        let as_bytes = element_count * size_of::<T>();
        s.blocks[0] = s
            .allocator
            .request(Layout::from_size_align(as_bytes, align_of::<T>()).unwrap())
            .as_ptr() as *mut MaybeUninit<T>;
        s.block_lengths[0] = element_count;
        s
    }

    // [...]

}
```

Allocating a new segment (`Self::alloc_block`) outside of `Self::new` happens
when the current segment is out of space in any appending method, for instance
`Self::push(T)`:

```rust
impl <T> SegmentedList<T> {
    // [...]

    #[inline(always)]
    fn alloc_block(&mut self, block: usize) {
        use std::alloc::Layout;
        use std::mem::{MaybeUninit, align_of, size_of};

        let elems = START_SIZE << block;
        let bytes = elems * size_of::<T>();
        let layout = Layout::from_size_align(bytes, align_of::<T>())
            .expect("Invalid layout for SegmentedList block");

        let ptr = self.allocator.request(layout).as_ptr() as *mut MaybeUninit<T>;
        debug_assert!(!ptr.is_null(), "SegmentedAlloc returned null");

        self.blocks[block] = ptr;
        self.block_lengths[block] = elems;
    }

    pub fn push(&mut self, v: T) {
        if self.block_lengths[self.cur_block] == 0 {
            self.alloc_block(self.cur_block);
        }

        unsafe {
            (*self.blocks[self.cur_block].add(self.offset_in_block)).write(v);
        }

        self.len += 1;
        self.offset_in_block += 1;

        if self.offset_in_block == self.block_lengths[self.cur_block] {
            self.cur_block += 1;
            self.offset_in_block = 0;
        }
    }

    pub fn get(&self, idx: usize) -> Option<&T> {
        if idx >= self.len {
            return None;
        }
        let SegmentedIdx(block, block_index) = self.idx_to_block_idx(idx);
        Some(unsafe { (*self.blocks[block].add(block_index)).assume_init_ref() })
    }

    // [...]
}
```

Since I want to provide somewhat of a `std::vec::Vec` drop in replacement, I
added a truckload of methods vec also supports. Due to the already way too
large nature of this article I'll restrict myself to `to_vec`, `capacity`,
`clear` and `impl<T: Clone + Copy> Clone for SegmentedList<T>`, since these
are somewhat non-trivial:

```rust
impl<T> SegmentedList<T> {
    /// Collects self and its contents into a vec
    pub fn to_vec(mut self) -> Vec<T> {
        let mut result = Vec::with_capacity(self.len);
        let mut remaining = self.len;

        for block_idx in 0..BLOCK_COUNT {
            if remaining == 0 {
                break;
            }

            let len = self.block_lengths[block_idx];
            if len == 0 {
                break;
            }

            let ptr = self.blocks[block_idx];
            let take = remaining.min(len);
            for i in 0..take {
                let value = unsafe { (*ptr.add(i)).assume_init_read() };
                result.push(value);
            }
            remaining -= take;
            // We "forget" the block, no dealloc, bump allocator manages memory
            self.blocks[block_idx] = std::ptr::null_mut();
        }
        result
    }

    pub fn capacity(&self) -> usize {
        self.block_lengths.iter().copied().sum()
    }

    pub fn clear(&mut self) {
        let mut remaining = self.len;
        for block_idx in 0..BLOCK_COUNT {
            if remaining == 0 {
                break;
            }
            let len = self.block_lengths[block_idx];
            let ptr = self.blocks[block_idx];
            if len == 0 {
                break;
            }
            let take = remaining.min(len);
            for i in 0..take {
                unsafe { (*ptr.add(i)).assume_init_drop() };
            }
            remaining -= take;
        }
        self.len = 0;
    }
}

impl<T: Clone + Copy> Clone for SegmentedList<T> {
    fn clone(&self) -> Self {
        let mut new_list = SegmentedList::new();
        new_list.len = self.len;

        for block_idx in 0..BLOCK_COUNT {
            if self.block_lengths[block_idx] == 0 {
                break;
            }
            let src_ptr = self.blocks[block_idx];
            let elems = self.block_lengths[block_idx];
            if elems == 0 {
                continue;
            }
            new_list.alloc_block(block_idx);
            let dst_ptr = new_list.blocks[block_idx];

            for i in 0..elems {
                unsafe {
                    let val = (*src_ptr.add(i)).assume_init();
                    (*dst_ptr.add(i)).write(val);
                }
            }
            new_list.block_lengths[block_idx] = elems;
        }

        new_list
    }
}
```

The attentive reader will have noticed I snuck some small optimisations in:

- Inline `alloc_block`, `idx_to_block_idx` (-2% runtime)
- Inline `mmap` and `munmap` (-4% runtime)
- precompute block boundaries in `BLOCK_STARTS` (-41% runtime)
- cache `SegmentedIdx` computation for `Self::push` via `cur_block` and
  `offset_in_block`
- remove unnecessary indirections (-8% runtime)

## segmented_rs::list::SegmentedList vs std::vec::Vec

Benchmarks are of course done with criterion:

```rust
// benches/list.rs
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use segmented_rs::list::SegmentedList;

pub fn bench_segmented_list(c: &mut Criterion) {
    fn bench_push<T: Clone>(c: &mut Criterion, name: &str, template: T, count: usize) {
        c.bench_function(name, |b| {
            b.iter_batched(
                || SegmentedList::new(),
                |mut list| {
                    for _ in 0..count {
                        list.push(black_box(template.clone()));
                    }
                    black_box(list)
                },
                BatchSize::SmallInput,
            )
        });
    }

    bench_push(c, "segmented_list_push_u64", 123u64, 10_000);

    #[derive(Clone)]
    struct MediumElem([u8; 40]);
    bench_push(c, "segmented_list_push_medium", MediumElem([42; 40]), 1_000);

    #[derive(Clone)]
    struct HeavyElem(Box<[u8]>);
    bench_push(
        c,
        "segmented_list_push_heavy_1MiB",
        HeavyElem(vec![161u8; 1 * 1024 * 1024].into_boxed_slice()),
        50,
    );
}

criterion_group!(benches, bench_segmented_list);
criterion_main!(benches);
```

The same for `std::vec::Vec`:

```rust
// benches/vec.rs
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};

pub fn bench_vec(c: &mut Criterion) {
    fn bench_push<T: Clone>(c: &mut Criterion, name: &str, template: T, count: usize) {
        c.bench_function(name, |b| {
            b.iter_batched(
                || Vec::new(),
                |mut vec| {
                    for _ in 0..count {
                        vec.push(black_box(template.clone()));
                    }
                    black_box(vec)
                },
                BatchSize::SmallInput,
            )
        });
    }

    bench_push(c, "vec_push_u64", 123u64, 10_000);

    #[derive(Clone)]
    struct MediumElem([u8; 40]);
    bench_push(c, "vec_push_medium", MediumElem([42; 40]), 1_000);

    #[derive(Clone)]
    struct HeavyElem(Box<[u8]>);
    bench_push(
        c,
        "vec_push_heavy_1MiB",
        HeavyElem(vec![161u8; 1 * 1024 * 1024].into_boxed_slice()),
        50,
    );
}

criterion_group!(benches, bench_vec);
criterion_main!(benches);
```

Both are runnable via `cargo bench --bench list`:

```text
segmented_list_push_u64         time:   [39.502 µs 40.156 µs 40.860 µs]
segmented_list_push_medium      time:   [35.512 µs 35.901 µs 36.306 µs]
segmented_list_push_heavy_1MiB  time:   [3.0590 ms 3.0932 ms 3.1345 ms]
segmented_list_push_heavy_10MiB time:   [3.3591 ms 3.3934 ms 3.4299 ms]
segmented_list_push_heavy_50MiB time:   [19.895 ms 20.425 ms 21.353 ms]
```

and `cargo bench --bench vec`:

```text
vec_push_u64            time:   [32.955 µs 33.463 µs 33.961 µs]
vec_push_medium         time:   [28.725 µs 29.058 µs 29.435 µs]
vec_push_heavy_1MiB     time:   [3.3439 ms 3.3816 ms 3.4236 ms]
vec_push_heavy_10MiB    time:   [3.7747 ms 3.8124 ms 3.8548 ms]
vec_push_heavy_50MiB    time:   [21.718 ms 21.865 ms 22.018 ms]
```

So it beats vec on larger elements (starting from 1MiB), but these are only
applicable when moving large amounts of giant blobs. The rust team did a great
job at optimising `std::vec::Vec`, my "naive" implementation comes near, but
only outperforms on very large workloads.

# Rust Pain Points

- Sync and Send have to be implemented for `std::alloc::GlobalAlloc`, I get the
  allocator has to be shared between threads, but its weird to have a nop impl
- `cargo test` executes tests concurrently and therefore crash if not run with
  `--test-threads=1`, which was fucking hard to debug, since these are flaky as
  hell, sometimes it happens, sometimes it doesnt:

  - illegal memory access:

    ```text
    running 24 tests
    error: test failed, to rerun pass `--lib`

    Caused by:
      process didn't exit successfully: 
      `/home/teo/programming/segmented-rs/target/debug/deps/segmented_rs-68ce766f62589be2` 
      (signal: 11, SIGSEGV: invalid memory reference)
    ```

  - `SendError` since `SegmentedAlloc` couldn't be send from a thread to another

    ```text
    thread 'main' panicked at library/test/src/lib.rs:463:73:
    called `Option::unwrap()` on a `None` value
    [Thread 0x7ffff691f6c0 (LWP 22634) exited]

    thread 'list::tests::stress_test_large_fill' panicked at library/test/src/lib.rs:686:30:
    called `Result::unwrap()` on an `Err` value: SendError { .. }
    ```

- Segfaults in Rust are worse to debug with `gdb` than in C, unaligned memory
  issues, segfaults and other invalid memory access are hard to pinpoint
- No stack traces for `panic!` when implementing `std::alloc::GlobalAlloc`, just:

  ```text
  panic:
  ```

  Gdb (most of the time) helps with the stacktrace when compiling with
  `RUSTFLAGS="-C debuginfo=2"`.

# What Rust does better than C (at least in this case)

- Generics, looking at you `_Generic`, Rust just did it better. To be fair,
  even Java did it better. What even is this:
  ```c
  #define DBG(EXPR) //...
  ({
    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wformat\"") __auto_type _val = (EXPR);
    fprintf(stderr, "[%s:%d] %s = ", __FILE__, __LINE__, #EXPR);
    _Generic((_val),
        int: fprintf(stderr, "%d\n", _val),
        long: fprintf(stderr, "%ld\n", _val),
        long long: fprintf(stderr, "%lld\n", _val),
        unsigned: fprintf(stderr, "%u\n", _val),
        unsigned long: fprintf(stderr, "%lu\n", _val),
        unsigned long long: fprintf(stderr, "%llu\n", _val),
        float: fprintf(stderr, "%f\n", _val),
        double: fprintf(stderr, "%f\n", _val),
        const char *: fprintf(stderr, "\"%s\"\n", _val),
        char *: fprintf(stderr, "\"%s\"\n", _val),
        default: fprintf(stderr, "<unprintable>\n"));
    _Pragma("GCC diagnostic pop") _val;
  })
  ```
  There isn't even a way to run different functions for differing datatypes,
  since each path has to compile and you can't pass something like a double to
  `strlen` even if this isn't really happening, gcc still complains, see
  [Workarounds for C11
  _Generic](https://www.chiark.greenend.org.uk/~sgtatham/quasiblog/c11-generic/).

- Drop implementations and traits in general are so much better than any C
  alternative, even though I can think of at least 3 shittier ways to emulate
  traits in C
- Enums are so much fun in Rust, I love variant "bodies"? The only thing
  tripping me up was that one can't use them to mirror the C flag behaviour for
  bitOring arguments.
- Builtin testing and benchmarking (the latter at least somewhat). I really
  miss Gos testing behaviour in Rust, but the default "workflow" is fine for my
  needs (table driven tests for the win)
- Compile time constructs, precomputing the starts of blocks allowed me to
  simplify my segment and offset lookup code by a whole lot, and its faster

Of course this comparison isn't that fair, since C is from the 70s and Rust has
learned from the shortcomings of the systems level programming languages coming
before it. I still like to program in C, particulary for the challenge and the
level of control it allows, but only with `-fsanitize=address,undefined` and
running valgrind a whole lot.
