---
title: "Porting a Segmented List From C to Rust"
summary: "Macros, Token pasting and Custom allocators vs Traits, `Option<Box<[MaybeUninit<T>]>>` and the borrow checker"
date: 2025-09-28
tags:
  - rust
  - c
draft: true
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

## Why Segmented Lists

Vectors suck at growing a lot, because:

1. They have to allocate a new and larger block
2. They have to copy their contents to the new space
3. They require to "update" all references into the previous space to the new
   space
4. For large `mem::size_of::<T>()`, copies are costly and require moving a lot
   of memory

### Design

### Indexing

## C Implementation

### Bump allocator

## Rust Implementation

### Handrolling x86 mmap & munmap syscalls

About using the `libc` crate: This would be against my mentality of not using
dependencies if possible and libc is a large one due to it pulling in the C
runtime for two syscalls I can just wrap myself using `asm!`.

{{<callout type="Warning">}}
Ofc the above is only correct on linux `#[no_std]` since in some cases rusts
std depends on libc, but you get what im trying to convey.
{{</callout>}}

My first step was porting their arguments into the rust typesystem. I couldn't
use rust enums, since they require variants to be exclusive, which the bit
flags for `READ`, `WRITE` and `PRIVATE`, `ANONYMOUS` arent. So i had to settle
for a struct containing `i32`. To support bit or(ed) flags for the arguments I
also had to quickly implement `std::ops::BitOr`:

```rust
const MMAP_SYSCALL: i32 = 9;
const MUNMAP_SYSCALL: i32 = 11;

// Not an enum, since READ and WRITE arent mutually exclusive
pub struct MmapProt(i32);

impl MmapProt {
    pub const READ: MmapProt = MmapProt(0x1);
    pub const WRITE: MmapProt = MmapProt(0x2);
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
    pub const PRIVATE: MmapFlags = MmapFlags(0x02);
    pub const ANONYMOUS: MmapFlags = MmapFlags(0x20);
    pub fn bits(self) -> i32 {
        self.0
    }
}

impl std::ops::BitOr for MmapFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        MmapFlags(self.0 | rhs.0)
    }
}
```

The functions themselves are pretty straightforward if you have ever called a
syscall from assembly. We use the `syscall` instruction and fill some registers
with the arguments according to the x86 calling convention:

| registers | value                                                         |
| --------- | ------------------------------------------------------------- |
| `rax`     | Syscall kind (`9` for `mmap`)                                 |
| `rdi`     | pointer or null for anonymous (`Option::None` for the latter) |
| `rsi`     | region length                                                 |
| `rdx`     | protection modifiers                                          |
| `r10`     | flags                                                         |
| `r8`      | file descriptor (`-1` for anonymous)                          |
| `r9`      | offset                                                        |

```rust
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
            options(nostack, preserves_flags, readonly)
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
pub fn munmap(ptr: std::ptr::NonNull<u8>, size: usize) {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") MUNMAP_SYSCALL,
            in("rdi") ptr.as_ptr(),
            in("rsi") size,
            lateout("rax") ret,
            options(nostack, preserves_flags, readonly)
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

## Runtime and Memory Comparison of C, Rust and std::vec::Vec

## Pain points
