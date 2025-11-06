---
title: "Strategies for very fast Lexers"
summary: "Making compilation pipelines fast, starting with the tokenizer"
date: 2025-07-14
math: true
tags:
  - c
  - pldev
---

In this blog post I'll explain strategies I used to make the purple garden
lexer really fast.

> [purple-garden](https://github.com/xNaCly/purple-garden) is an s-expr based
> language I am currently developing for myself. Its my attempt at building a
> language I like, with a battery included approach, while designing it with
> performance in mind.

This doesn't mean all approaches are feasible for your use case, architecture
and design. I tried to bring receipts for my performance claims, so
watch out for these blocks at the end of chapters:

{{<callout type="Info - Benchmark">}}
{{</callout>}}

# Introduction to Lexing

A lexer (often also referred to as a tokeniser) is the easiest part of any compilation and
language pipeline. The idea is to convert a list of characters into a list of
tokens in which each token conveys some meaning. This list of tokens can then
be used by the parser to generate an abstract syntax tree (AST), which the
compiler consumes, converting it to bytecode, which the vm executes.

## A compilation pipeline

As an overview:

```
┌───────────────────┐
│                   │
│       Lexer       │ <- we are here
│                   │
└─────────┬─────────┘
          │
          │ Tokens <- and here
          │
┌─────────▼─────────┐
│                   │
│       Parser      │
│                   │
└─────────┬─────────┘
          │
          │ AST
          │
┌─────────▼─────────┐
│                   │
│      Compiler     │
│                   │
└─────────┬─────────┘
          │
          │ Bytecode
          │
┌─────────▼─────────┐
│                   │
│  Virtual Machine  │
│                   │
└───────────────────┘
```

For a list of characters, lets say `(@std.fmt.println "my pi is: " 3.1415)`:

1. Input to the lexer:

   ```text
   (@std.fmt.println "my pi is: " 3.1415)
   ```

2. As characters:

   ```text
   (
   @
   s
   t
   d
   .
   f
   m
   t
   // ....
   )
   ```

3. As pseudo tokens:

   ```text
   (
   @std
   .
   fmt
   .
   println
   "my pi is: "
   3.1415
   )
   ```

The above is just an example and I'll go into detail below:

## Defining purple garden's Tokens

A token is not only a set of characters it can be mapped to, but it also holds:

- A token type, to easily distinguish between tokens
- Positional information:
  - start point
  - end or length
  - line number

Purple garden keeps it as minimal as possible and just has a String and a token type:

```c
typedef enum {
  // (
  T_DELIMITOR_LEFT = 1,
  // +
  T_PLUS = 2,
  // -
  T_MINUS = 3,
  // *
  T_ASTERISKS = 4,
  // /
  T_SLASH = 5,
  // =
  T_EQUAL = 6,
  // )
  T_DELIMITOR_RIGHT,
  // [
  T_BRAKET_LEFT,
  // ]
  T_BRAKET_RIGHT,
  // anything between ""
  T_STRING,
  // true
  T_TRUE,
  // false
  T_FALSE,
  // floating point numbers
  T_DOUBLE,
  // whole numbers
  T_INTEGER,
  // builtins in the format @<builtin>
  T_BUILTIN,
  // any identifier
  T_IDENT,
  // end marker
  T_EOF,
} TokenType;

typedef struct {
  TokenType type;
  // stores all values for T_STRING,T_IDENT,T_INTEGER and T_DOUBLE
  Str string;
} Token;
```

## Architecting a minimal Lexer

As explained in [A compilation pipeline](#a-compilation-pipeline), the lexer
iterates over the characters in the input and attempts to match found
characters to sets of characters, like keywords, numbers and symbols. For this
we will need to keep some state, even if though its not much:

```c
typedef struct {
  Str input; // <- String view over the input
  size_t pos; // <- current position in the input
} Lexer;
```

> `Str` as an abstraction is introduced in [Operating on zero copy, zero alloc string windows](#operating-on-zero-copy-zero-alloc-string-windows).

A naive approach would be:

```c
#define SINGLE_TOK(t) ((Token){.type = t})

Lexer Lexer_new(Str str) {
    return {
        .input=str,
        .pos=0
    };
}

Token Lexer_next(Lexer *l) {
    if (l->input.len == 0 || l->pos >= l->input.len) {
        return SINGLE_TOK(T_EOF)
    }

    Token t;
    switch(Str_get(l->input, l->pos)) {
        case '+':
            t = SINGLE_TOK(T_PLUS);
            break;
        case '-':
            t = SINGLE_TOK(T_MINUS);
            break;
        case '*':
            t = SINGLE_TOK(T_ASTERISKS);
            break;
        case '/':
            t = SINGLE_TOK(T_SLASH);
            break;
        // ... thinks like strings, quoted symbols, numbers, comments, whitespace :^)
        default:
            t = SINGLE_TOK(T_EOF);
            break;
    }
    l->pos++;
    return t;
}
```

And one could consume the api as follows (even with a little type->string
lookup for debugging):

```c
const char* TOKEN_TYPE_MAP[] = {
    [T_PLUS] = "T_PLUS",
    [T_MINUS] = "T_MINUS",
    [T_ASTERISKS] = "T_ASTERISKS",
    [T_SLASH] = "T_SLASH",
    [T_EOF] = "T_EOF"
};

Str s = STRING("+-*/");
Lexer l = Lexer_new(s);
while(l.pos < l.input.len) {
    Token t = Lexer_next(&l);
    puts(TOKEN_TYPE_MAP[t.type]);
}
```

{{<callout type="Tip - Designated initializers">}}
Designated initializers (`[<int>] = <value>`) are allowed by ISO C99, while
designated initializers with ranges (`[<int> .. <int>] = <value>`) are a gnu
extension, see [6.2.11 Designated Initializers
](https://gcc.gnu.org/onlinedocs/gcc/Designated-Inits.html).
{{</callout>}}

# Making it fast

Lets get into some optimisations and strategies for creating a clean, minimal
and especially fast lexer.

## Computed gotos, or: Threaded Lexing

`Threaded Lexing` is a reference to _Threaded code_, see
[wikipedia](https://en.wikipedia.org/wiki/Threaded_code). The idea is to
replace the switch statement with a jump to a block inside of the lexer. The
easiest way I could think of implementing this was to:

1. Define a jump table mapping lexeme start characters to their respective blocks

   ```c
   static void *jump_table[256] = {
     // first bind all possible bytes to the unknown label, so there are no out
     // of bound reads
     [0 ... 255] = &&unknown,

     // replace all known bytes with correct jump labels
     ['('] = &&delimitor_left,
     [')'] = &&delimitor_right,
     ['['] = &&bracket_left,
     [']'] = &&bracket_right,
     ['@'] = &&builtin,
     ['+'] = &&plus,
     ['-'] = &&minus,
     ['/'] = &&slash,
     ['*'] = &&asterisk,
     ['='] = &&equal,
     [' '] = &&whitespace,
     ['\t'] = &&whitespace,
     ['\n'] = &&whitespace,
     [';'] = &&comment,
     ['.'] = &&number,
     ['0' ... '9'] = &&number,
     ['a' ... 'z'] = &&ident,
     ['A' ... 'Z'] = &&ident,
     ['\''] = &&quoted,
     ['_'] = &&ident,
     ['"'] = &&string,

     // handle the edgecase of being at the end of the input
     [0] = &&end,
   };
   ```

2. Create a macro for jumping to the label

   ```c
   #define JUMP_TARGET goto *jump_table[(int8_t)l->input.p[l->pos]]
   ```

3. At the start of the lexer, call the macro

   ```c
   JUMP_TARGET
   ```

Putting it all together lets us build the following threaded lexer:

```c
size_t Lexer_all(Lexer *l, Allocator *a, Token **out) {
  ASSERT(out != NULL, "Failed to allocate token list");

  // empty input
  if (l->input.len == 0) {
    return 1;
  }

  static void *jump_table[256] = {
      [0 ... 255] = &&unknown,
      ['('] = &&delimitor_left,
      [')'] = &&delimitor_right,
      ['['] = &&bracket_left,
      [']'] = &&bracket_right,
      ['@'] = &&builtin,
      ['+'] = &&plus,
      ['-'] = &&minus,
      ['/'] = &&slash,
      ['*'] = &&asterisk,
      ['='] = &&equal,
      [' '] = &&whitespace,
      ['\t'] = &&whitespace,
      ['\n'] = &&whitespace,
      [';'] = &&comment,
      ['.'] = &&number,
      ['0' ... '9'] = &&number,
      ['a' ... 'z'] = &&ident,
      ['A' ... 'Z'] = &&ident,
      ['\''] = &&quoted,
      ['_'] = &&ident,
      ['"'] = &&string,
      [0] = &&end,
  };

#define JUMP_TARGET goto *jump_table[(int8_t)l->input.p[l->pos]]

  JUMP_TARGET;

delimitor_left:
  JUMP_TARGET;

delimitor_right:
  JUMP_TARGET;

bracket_left:
  JUMP_TARGET;

bracket_right:
  JUMP_TARGET;

builtin:
  JUMP_TARGET;

plus:
  JUMP_TARGET;

minus:
  JUMP_TARGET;

slash:
  JUMP_TARGET;

equal:
  JUMP_TARGET;

asterisk:
  JUMP_TARGET;

number:
  JUMP_TARGET;

ident:
  JUMP_TARGET;

quoted:
  JUMP_TARGET;

string:
  JUMP_TARGET;

comment:
  JUMP_TARGET;

whitespace:
  JUMP_TARGET;

unknown:
  return 1;

end:
  return 0;
}
```

Replacing the switch with an array index and a jump. The latter is
significantly faster than the former due to:

- Better [code density](https://en.wikipedia.org/wiki/Instruction_set_architecture#Code_density)
- Less cache misses, better branch prediction

{{<callout type="Warning">}}
There are two downsides to this approach:

1. It is not supported by MSVC toolchain (clang, gcc only)
2. It makes reading and debugging the lexer far more complicated
   {{</callout>}}

## Abstracting allocations via the Allocator interface

I want to allow the user of purple-garden to choose between allocation
strategies like my garbage collectors and a bump allocator. For this I need an
interface to marry several backing implementations into a singular api:

```c
#ifndef MEM_H
#define MEM_H

#include <stddef.h>

#ifdef DEBUG
#if DEBUG
#define VERBOSE_ALLOCATOR 1
#endif
#else
#define VERBOSE_ALLOCATOR 0
#endif

// 1MB
#define GC_MIN_HEAP 1024 * 1024

typedef struct {
  size_t current;
  size_t allocated;
} Stats;

// CALL is used to emulate method calls by calling a METHOD on SELF with
// SELF->ctx and __VA_ARGS__, this is useful for interface interaction, such as
// Allocator, which reduces alloc_bump.request(alloc_bump.ctx, 64); to
// CALL(alloc_bump, request, 64), removing the need for passing the context in
// manually
#if VERBOSE_ALLOCATOR
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
//  Allocator alloc_bump = bump_init(ALLOC_HEAP_SIZE);
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

Allocator *bump_init(size_t size);
Allocator *xcgc_init(size_t size, void *vm);

#endif
```

For instance: this allocator is then passed to the virtual machine. The vm uses
`Allocator->request(Allocator->ctx, sizeof(Value))` to allocate a new runtime
value.

I included a `CALL` macro for cleaning this duplicated context passing up:

```c
Allocator *a = bump_init(1024);

// before:
void *block = a->request(a->ctx, 512);
a->destroy(a->ctx)

// after:
void *block = CALL(a, request, 512);
CALL(a, destroy)
```

This macro also enables verbose allocation insights for debugging purposes:

```text
[ALLOCATOR] vm.c@freelist_preallocate::59: fl->alloc->request(sizeof(Frame))
[ALLOCATOR] main.c@main::245: vm.alloc->stats()
[ALLOCATOR] main.c@main::255: pipeline_allocator->destroy()
[ALLOCATOR] vm.c@Vm_destroy::283: vm->alloc->destroy()
```

The implementation of said interface is straightforward:

```c
// Bump allocator header
typedef struct {
  // points to the start of the allocated block from which Allocator::request
  // will hand out aligned chunks
  void *block;
  // the size of said allocated block
  size_t len;
  // the current amount of bytes in use
  size_t pos;
} BumpCtx;

void *bump_request(void *ctx, size_t size) {
  BumpCtx *b_ctx = (BumpCtx *)ctx;
  size_t align = sizeof(void *);
  b_ctx->pos = (b_ctx->pos + align - 1) & ~(align - 1);
  ASSERT(b_ctx->pos + size <= b_ctx->len, "OOM :( with %zu", b_ctx->len);
  void *block_entry = (char *)b_ctx->block + b_ctx->pos;
  b_ctx->pos += size;
  return block_entry;
}

void bump_destroy(void *ctx) {
  ASSERT(ctx != NULL, "bump_destroy on already destroyed allocator");
  BumpCtx *b_ctx = (BumpCtx *)ctx;
  // madvise(2):
  // The  application  no  longer requires the pages in the range
  // specified by addr and len. The kernel can thus  free  these
  // pages,  but  the freeing could be delayed until memory pres‐
  // sure occurs.
  madvise(b_ctx->block, b_ctx->len, MADV_FREE);
  int res = munmap(b_ctx->block, b_ctx->len);
  ASSERT(res == 0, "munmap failed");
  free(ctx);
}

Stats bump_stats(void *ctx) {
  BumpCtx *b_ctx = (BumpCtx *)ctx;
  return (Stats){.allocated = b_ctx->len, .current = b_ctx->pos};
}

Allocator *bump_init(size_t size) {
  long page_size = sysconf(_SC_PAGESIZE);
  size = (size + page_size - 1) & ~(page_size - 1);

  void *b = mmap(NULL, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT(b != MAP_FAILED, "failed to mmap allocator buffer");

  BumpCtx *ctx = malloc(sizeof(BumpCtx));
  ASSERT(ctx != NULL, "failed to bump allocator context");
  ctx->len = size;
  ctx->pos = 0;
  ctx->block = b;

  Allocator *a = malloc(sizeof(Allocator));
  ASSERT(ctx != NULL, "failed to alloc bump allocator");
  a->ctx = (void *)ctx;
  a->destroy = bump_destroy;
  a->request = bump_request;
  a->stats = bump_stats;

  return a;
}
```

{{<callout type="Info - Benchmarks">}}

This reduced the total runtime by like 24ms or made it 1.58x faster, see
[`4251b6b`](https://github.com/xNaCly/purple-garden/commit/4251b6b9fd701d7e1f7fd9a6e783000aa465f8ff).

_The separate parsing stage was due to me experimenting with attaching the
parser to the compiler, but this made the whole thing a bit slower than just
finishing parsing before compiling_

```text
mem+main+cc: replace dynamic alloc with bump allocator (~1.6x faster)
- preallocated 4MB for bytecode and 256KB for the global pool to improve memory management.
- cc now takes an allocator to omit inline memory allocations for global
  pool entries and bytecode creation
- with previous changes shaving off 24ms

Old perf (before b59737a)

    [    0.0070ms] main::Args_parse: Parsed arguments
    [    0.0080ms] io::IO_read_file_to_string: mmaped input
    [   41.2460ms] parser::Parser_run: Transformed source to AST
    [   20.7330ms] cc::cc: Flattened AST to byte code
    [    0.9640ms] mem::Allocator::destroy: Deallocated AST memory space
    [    2.1270ms] vm::Vm_run: Walked and executed byte code
    [    0.5560ms] vm::Vm_destroy: Deallocated global pool and bytecode list

New:

    [    0.0050ms] main::Args_parse: Parsed arguments
    [    0.0120ms] io::IO_read_file_to_string: mmaped input
    [   37.8600ms] cc::cc: Flattened AST to byte code
    [    2.3540ms] vm::Vm_run: Walked and executed byte code
    [    0.7380ms] mem::Allocator::destroy: Deallocated AST memory space

    $ hyperfine "./purple_garden examples/bench.garden" "../purple_garden_old/purple_garden examples/bench.garden"
    Benchmark 1: ./purple_garden examples/bench.garden
      Time (mean ± σ):      42.2 ms ±   0.7 ms    [User: 28.0 ms, System: 13.8 ms]
      Range (min … max):    41.3 ms …  45.8 ms    70 runs

    Benchmark 2: ../purple_garden_old/purple_garden examples/bench.garden
      Time (mean ± σ):      66.6 ms ±   1.1 ms    [User: 45.9 ms, System: 20.2 ms]
      Range (min … max):    64.8 ms …  69.8 ms    43 runs

    Summary
      ./purple_garden examples/bench.garden ran
        1.58 ± 0.04 times faster than ../purple_garden_old/purple_garden examples/bench.garden
```

Before I also made the parser use the block allocator, see
[`0324051`](https://github.com/xNaCly/purple-garden/commit/032405134150b4fb6669812320089f1851c3cb8b):

```text
parser: allocate with bump alloc (2x faster parse, 26x faster clean)
I replaced the inline allocation logic for the growing of Node.children with
the bump allocator from the allocator abstraction in mem::Allocator
(mem::bump_*). This results in 2x faster parsing and 27x faster AST cleanup:

- [   89.4830ms/41.7840ms=02.1417x faster] parser::Parser_run: Transformed
  source to AST
- [   22.3900ms/00.8440ms=26.5284x faster] parser::Node_destroy: Deallocated
  AST Nodes renamed to mem::Allocator::destroy

Old:

    $ make bench PG=examples/bench.garden
    [    0.0050ms] main::Args_parse: Parsed arguments
    [    0.0110ms] io::IO_read_file_to_string: mmaped input
    [   89.4830ms] parser::Parser_run: Transformed source to AST
    [   18.8010ms] cc::cc: Flattened AST to byte code
    [   22.3900ms] parser::Node_destroy: Deallocated AST Nodes
    [    2.3200ms] vm::Vm_run: Walked and executed byte code
    [    0.4670ms] vm::Vm_destroy: Deallocated global pool and bytecode list

New:

    $ make bench PG=examples/bench.garden
    [    0.0050ms] main::Args_parse: Parsed arguments
    [    0.0100ms] io::IO_read_file_to_string: mmaped input
    [   41.7840ms] parser::Parser_run: Transformed source to AST
    [   21.2160ms] cc::cc: Flattened AST to byte code
    [    0.8440ms] mem::Allocator::destroy: Deallocated AST memory space
    [    2.2510ms] vm::Vm_run: Walked and executed byte code
    [    0.7590ms] vm::Vm_destroy: Deallocated global pool and bytecode list
```

{{</callout>}}

## Operating on zero copy, zero alloc string windows

Our lexer doesn't require mutable strings, C does not come with a string
abstraction out of the box and I wanted to attach metadata to strings - so I
came up with a small string abstraction:

```c
// str is a simple stack allocated wrapper around C char arrays, providing
// constant time length access and zero allocation+copy interactions for all
// methods except Str_to
typedef struct {
  // store the pointer to the underlying char
  const uint8_t *p;
  // hash of the input, do not expect it to be filled, has to be computed via
  // Str_hash or inline in the lexer
  uint64_t hash;
  // length of the input without a zero terminator
  size_t len;
} Str;
```

```c
#define STRING(str) ((Str){.len = sizeof(str) - 1, .p = (const uint8_t *)str})
#define STRING_EMPTY ((Str){.len = 0, .p = NULL})

```

Creating a `Str` from a c style `const char*` can be done by passing it into
the `STRING` macro, gcc can evaluate all operations inside of it at compile
time. Since the view doesn't own its underlying data, its cheap to copy and
create slices by just pointing new views to the underlying buffer.

I use this struct throughout the whole codebase, but specifically inside of the
lexer to create views over the original input that point to the contents of
some tokens:

```c
// example inside of handling strings in the lexer:

// dummy values for start and hash
size_t start = 3;
size_t hash = 0xAFFEDEAD;

Token *t = &(Token){};
t->type = T_STRING;
t->string = (Str){
    .p = l->input.p + start,
    .len = l->pos - start,
    .hash = hash,
};
```

Due to the window nature of this struct I had to reimplement some things
myself, such as slicing, concatination, equality checking, hashing and
converting to `int64` and `double`:

```c
char Str_get(const Str *str, size_t index);
Str Str_from(const char *s);
Str Str_slice(const Str *str, size_t start, size_t end);
Str Str_concat(const Str *a, const Str *b, Allocator *alloc);
bool Str_eq(const Str *a, const Str *b);
void Str_debug(const Str *str);
size_t Str_hash(const Str *str);
int64_t Str_to_int64_t(const Str *str);
double Str_to_double(const Str *str);
```

Lets quickly go over the interesting ones, specifically slicing and converting
to other data types. Slicing is super easy, since we just move the start and
the end to the new slice start and end.

```c
Str Str_slice(const Str *str, size_t start, size_t end) {
  ASSERT(end >= start, "Str_slice: Invalid slice range: end must be >= start");
  ASSERT(end <= str->len, "Str_slice: Slice range exceeds string length");

  return (Str){
      .p = str->p + start,
      .len = end - start,
  };
}
```

Converting to `int64` is also fairly uncomplicated, since the lexer is expected
to make sure all characters are in the integer set. The algorithm consists of
converting the character representation of an integer component into its
literal value by subtracting `'0'` from it. The resulting value is added to the
product of the previous iteration and 10, since we are working in the decimal
system.

```c
int64_t Str_to_int64_t(const Str *str) {
  int64_t r = 0;
  ASSERT(str->len > 0, "Cant convert empty string into int64_t");

  for (size_t i = 0; i < str->len; i++) {
    int digit = str->p[i] - '0';
    ASSERT(r < (INT64_MAX - digit) / 10,
           "int64_t number space overflow: `%.*s`", (int)str->len, str->p)
    r = r * 10 + digit;
  }

  return r;
}
```

Doubles are represented differently, specifcally by their mantiassa and
exponent, requiring a slightly more sophisticated conversion algorithm. In the
same vein as `Str_to_int64_t`, validating is already done by the lexer to the
extend of only allowing any of `.1234567890`.

```c
double Str_to_double(const Str *str) {
  ASSERT(str->len > 0, "Can't convert empty string into double");

  const char *p = (const char *)str->p;
  size_t len = str->len;

  uint64_t mantissa = 0;
  int exponent = 0;
  bool seen_dot = false;
  bool has_digits = false;

  // we dont check that all chars are numbers here, since the lexer already does
  // that
  for (size_t i = 0; i < len; i++) {
    char c = p[i];

    if (c == '.') {
      seen_dot = true;
      continue;
    }

    has_digits = true;
    short digit = c - '0';
    ASSERT(mantissa <= (UINT64_MAX - digit) / 10, "Mantissa overflow");
    mantissa = mantissa * 10 + digit;
    if (seen_dot) {
      exponent -= 1;
    }
  }

  // if there were no digits after the '.'
  ASSERT(has_digits, "Can't parse `%.*s` into a double", (int)len, p);

  double result = (double)mantissa;
  // skip exponent computation for <mantissa>.0, since these are just the
  // mantissa
  if (exponent != 0) {
    result *= pow(10.0, exponent);
  }

  return result;
}
```

{{<callout type="Info - Benchmarks">}}
1.4x Speedup by using the above abstraction in a non allocating way, see
[`b19088a`](https://github.com/xNaCly/purple-garden/commit/b19088a61ec5f5e723036fe8cd1161c3a1fecc44):

```text
common: make String methods 0 alloc (~1.4x faster)
- String_slice no longer requires a malloc, now just returns a window into its
  argument
- String_to no longer returns just the underlying pointer (String.p) but
  allocates a new char*
- new String_debug method to print the window
- lexer::num no longer allocates and frees for its string window, instead uses
  a stack buffer
- parser::Node_destroy no longer calls Token_destroy
- Token_destroy no longer needed, since the lexer no longer allocates

Main improvements in runtime while parsing (less allocations and frees for
ident, string and double handling) and in cleanup (no more deallocations for
tokens)

With 250k loc of "hello world":

- Parsing went from 20.9ms to 13.8ms => 1.51x faster
- Cleanup went from 3.6ms to 0.83ms => 4.34x faster

Old:

    [BENCH] (T-0.0060ms): parsed arguments
    [BENCH] (T-0.0420ms): read file to String
    [BENCH] (T-20.8780ms): parsed input
    [BENCH] (T-6.8080ms): compiled input
    [BENCH] (bc=500002|globals=250001)
    [BENCH] (T-0.3440ms): ran vm
    [BENCH] (T-3.5960ms): destroyed Nodes, vm and input

New:

    [BENCH] (T-0.0060ms): parsed arguments
    [BENCH] (T-0.0410ms): read file to String
    [BENCH] (T-13.8280ms): parsed input
    [BENCH] (T-7.9410ms): compiled input
    [BENCH] (bc=500002|globals=250001)
    [BENCH] (T-0.3490ms): ran vm
    [BENCH] (T-0.8280ms): destroyed Nodes, vm and input
```

{{</callout>}}

## Hashing everything

I want to distinguish atoms (strings, numbers, idents) from other atoms for
interning purposes and faster comparisons in the pipeline. This can be done via
hashes, especially since we already "visit" each member of said atoms while
converting them to tokens. Hashing them is therefore just a matter of
computations while walking the atoms underlying bytes.

For instance strings: before this, the lexer just advanced until it hit the closing delimitor or EOF:

```c
size_t Lexer_all(Lexer *l, Allocator *a, Token **out) {

    // ...

string: {
  // skip "
  l->pos++;
  size_t start = l->pos;
  for (char cc = cur(l); cc > 0 && cc != '"'; l->pos++, cc = cur(l)) {}

  if (UNLIKELY(cur(l) != '"')) {
    Str slice = Str_slice(&l->input, l->pos, l->input.len);
    fprintf(stderr, "lex: Unterminated string near: '%.*s'", (int)slice.len,
            slice.p);
    out[count++] = INTERN_EOF;
  } else {
    Token *t = CALL(a, request, sizeof(Token));
    t->type = T_STRING;
    t->string = (Str){
        .p = l->input.p + start,
        .len = l->pos - start,
    };
    out[count++] = t;
    // skip "
    l->pos++;
  }
  JUMP_TARGET;
}

    // ...

}
```

Adding hashing to this is fairly easy:

```diff
diff --git a/lexer.c b/lexer.c
index 316a494..2280a6b 100644
--- a/lexer.c
+++ b/lexer.c
@@ -286,10 +286,7 @@ string: {
   // skip "
   l->pos++;
   size_t start = l->pos;
+  size_t hash = FNV_OFFSET_BASIS;
   for (char cc = cur(l); cc > 0 && cc != '"'; l->pos++, cc = cur(l)) {
+    hash ^= cc;
+    hash *= FNV_PRIME;
   }

   if (UNLIKELY(cur(l) != '"')) {
@@ -303,7 +300,6 @@ string: {
     t->string = (Str){
         .p = l->input.p + start,
         .len = l->pos - start,
+        .hash = hash,
     };
     out[count++] = t;
     // skip "
```

Numbers, identifiers and builtins are all also being hashed, I omitted this
here for clearity and since we will revisit this topic again in this article.

## Interning Tokens

Most of the tokens we will encounter are constant, we know:

- their size
- their type

We can use this knowledge, statically allocate these and use their pointers to
reduce memory pressure:

```c
// we can "intern" these, since all of them are the same, regardless of position
Token *INTERN_DELIMITOR_LEFT = &SINGLE_TOK(T_DELIMITOR_LEFT);
Token *INTERN_DELIMITOR_RIGHT = &SINGLE_TOK(T_DELIMITOR_RIGHT);
Token *INTERN_BRAKET_LEFT = &SINGLE_TOK(T_BRAKET_LEFT);
Token *INTERN_BRAKET_RIGHT = &SINGLE_TOK(T_BRAKET_RIGHT);
Token *INTERN_MINUS = &SINGLE_TOK(T_MINUS);
Token *INTERN_PLUS = &SINGLE_TOK(T_PLUS);
Token *INTERN_ASTERISKS = &SINGLE_TOK(T_ASTERISKS);
Token *INTERN_SLASH = &SINGLE_TOK(T_SLASH);
Token *INTERN_FALSE = &SINGLE_TOK(T_FALSE);
Token *INTERN_TRUE = &SINGLE_TOK(T_TRUE);
Token *INTERN_EQUAL = &SINGLE_TOK(T_EQUAL);
Token *INTERN_EOF = &SINGLE_TOK(T_EOF);

// size_t Lexer_all(Lexer *l, Allocator *a, Token **out)
```

`SINGLE_TOK` is just:

```c
#define SINGLE_TOK(t) ((Token){.type = t})
```

## Prehashing keywords for comparisons

As introduced in the previous chapters, all identifers are hashed, thus we can
also hash the known keywords at startup and make comparing them very fast.

Lets take a look at `true` and `false`, both are known keywords and we will
need to compare found identifers to them.

```c {hl_lines=[12]}
ident: {
  size_t start = l->pos;
  size_t hash = FNV_OFFSET_BASIS;
  for (char cc = cur(l); cc > 0 && is_alphanum(cc); l->pos++, cc = cur(l)) {
    hash ^= cc;
    hash *= FNV_PRIME;
  }

  size_t len = l->pos - start;
  Token *t;

  // comparing to the keywords is now just a number comparison
  if (hash == true_hash) {
    t = INTERN_TRUE;
  } else if (hash == false_hash) {
    t = INTERN_FALSE;
  } else {
    t = CALL(a, request, sizeof(Token));
    t->type = T_IDENT;
    t->string = (Str){
        .p = l->input.p + start,
        .len = len,
        .hash = hash,
    };
  }
  out[count++] = t;
  JUMP_TARGET;
}
```

Both `true_hash` and `false_hash` are computed at startup of `Lexer_all`:

```c {hl_lines=[10,11]}
size_t Lexer_all(Lexer *l, Allocator *a, Token **out) {
  ASSERT(out != NULL, "Failed to allocate token list");

  // empty input
  if (l->input.len == 0) {
    out[0] = INTERN_EOF;
    return 1;
  }

  size_t true_hash = Str_hash(&STRING("true"));
  size_t false_hash = Str_hash(&STRING("false"));

  // [...]
}
```

{{<callout type="Tip - is_alphanum performance deep dive">}}

> I know this function shouldn't be called `is_alphanum` because it allows `[A-Za-z0-9_-]`

A naive check of `is_alphanum` can be:

```c
bool is_alphanum(char cc) {
    return (cc >= 'a' && cc <= 'z') || (cc >= 'A' && cc <= 'Z')
        || (cc >= '0' && cc <= '9') || cc == '_' || cc == '-'
}
```

We know we can omit the uppercase check by converting the character to its
lowercase representation, so lets fold the character, since ASCII upper and
lowercase characters only differ by a single bit:

```c
bool is_alphanum(char cc) {
  uint8_t lower = cc | 0x20;
  bool is_alpha = (lower >= 'a' && lower <= 'z');
  bool is_digit = (cc >= '0' && cc <= '9');
  return is_alpha || is_digit || cc == '_' || cc == '-';
}
```

In benchmarks I was able to measure `inline` and parameter type `uint8_t` have a
reproducible impact of reducing the runtime by 1-5% for identifier heavy
inputs, so I marked the function as "private" `static inline`:

```c
__attribute__((always_inline)) inline static bool is_alphanum(uint8_t cc) {
  uint8_t lower = cc | 0x20;
  bool is_alpha = (lower >= 'a' && lower <= 'z');
  bool is_digit = (cc >= '0' && cc <= '9');
  return is_alpha || is_digit || cc == '_' || cc == '-';
}
```

There are some other ways that could be more efficient, but I haven't benchmarked these:

1. statically allocated lookup table like:

   ```c
   static const bool is_alphanum_lookup[128] = {
       ['0' ... '9'] = true,
       ['A' ... 'Z'] = true,
       ['a' ... 'z'] = true,
       ['_'] = true,
       ['-'] = true,
   };
   __attribute__((always_inline)) inline static bool is_alphanum(uint8_t cc) {
       return cc < 128 && is_alphanum_lookup[cc];
   }
   ```

2. weird bit sets:

   > I don't fully understand this one and it sucks to read, so no thanks

   ```c
   static const uint64_t table1 = 0x03ff000000000000
   static const uint64_t table2 = 0x07fffffe07fffffe

    __attribute__((always_inline)) inline static bool is_alphanum(uint8_t cc) {
       if (cc >= 128) return false;
       return cc < 64 ? (table1 >> cc) & 1 : (table2 >> (cc - 64)) & 1;
   }
   ```

{{</callout>}}

## On demand double and int64_t parsing

Let's revisit hashing numbers: as introduced before, all atoms are hashed,
therefore I am able to use this hash for and while interning. This way the
compiler converts all duplicated integers and doubles into their numerical
representation only once (in the compiler).

The lexer therefore only needs to store the window of the atoms input. While
verifying all characters in this window are valid arguments for `Str_to_double`
and `Str_to_int64_t`. In a later chapter I'll show the compiler doing on demand
parsing with the token we created here in the lexer.

```c
number: {
  size_t start = l->pos;
  size_t i = start;
  bool is_double = false;
  size_t hash = FNV_OFFSET_BASIS;
  for (; i < l->input.len; i++) {
    char cc = l->input.p[i];
    hash ^= cc;
    hash *= FNV_PRIME;
    if (cc >= '0' && cc <= '9')
      continue;
    if (cc == '.') {
      ASSERT(!is_double, "Two dots in double");
      is_double = true;
      continue;
    }
    break;
  }

  l->pos = i;
  Token *n = CALL(a, request, sizeof(Token));
  n->string = (Str){
      .p = l->input.p + start,
      .len = i - start,
      .hash = hash,
  };
  if (is_double) {
    n->type = T_DOUBLE;
  } else {
    n->type = T_INTEGER;
  }

  out[count++] = n;
  JUMP_TARGET;
}
```

{{<callout type="Tip - Distinguishing between integers and doubles">}}
At first, purple garden's runtime represented all numbers as doubles. After
benchmarking, I found out that integer math is a lot faster, so it makes a lot
more sense to store all non floating point numbers as integers. For general
advice, always benchmark and read the following:

- [Int VS FP performance](https://alammori.com/benchmarks/int-vs-fp-performance) (java, but
  the point stands)
- [6.2.2 Integer benefits and pitfalls - GNU Astronomy Utilities](https://www.gnu.org/software/gnuastro/manual/html_node/Integer-benefits-and-pitfalls.html)
- [Integer operations vs floating point operations on Computational Science Stack Exchange](https://scicomp.stackexchange.com/questions/30353/integer-operations-vs-floating-point-operations)

{{</callout>}}

## Extra: memory mapping the input

Normaly one would consume a file in C by

1. open file descriptor: `fopen`
2. fread the buffer into a malloced space
3. zero terminate
4. close file: `fclose`

```c
// https://stackoverflow.com/questions/14002954/c-how-to-read-an-entire-file-into-a-buffer
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("textfile.txt", "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *string = malloc(fsize + 1);
    fread(string, fsize, 1, f);
    fclose(f);

    string[fsize] = 0;
    free(string);
    return EXIT_SUCCESS;
}
```

However, you can also do the whole thing a lot faster by instructing the kernel
to dump the whole file into our virtual memory via
[`mmap`](https://www.man7.org/linux/man-pages/man3/mmap.3p.html) (Just not
walking a file two times is already faster).

After opening the file (opening a file with `O_RDONLY` and mapping it with
`PROT_READ` can be faster than making it mutable), we need it's type (we dont't
want to open or dump a directory) and it's size (the api wants a mapping block
size). [`fstat`](https://www.man7.org/linux/man-pages/man3/fstat.3p.html) helps
us with filling a struct with meta data containing exactly the info we need:

```c
// taken from https://www.commandlinux.com/man-page/man2/fstat.2.html
struct stat {
    dev_t     st_dev;     /* ID of device containing file */
    ino_t     st_ino;     /* inode number */
    mode_t    st_mode;    /* protection */
    nlink_t   st_nlink;   /* number of hard links */
    uid_t     st_uid;     /* user ID of owner */
    gid_t     st_gid;     /* group ID of owner */
    dev_t     st_rdev;    /* device ID (if special file) */
    off_t     st_size;    /* total size, in bytes */
    blksize_t st_blksize; /* blocksize for file system I/O */
    blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
    time_t    st_atime;   /* time of last access */
    time_t    st_mtime;   /* time of last modification */
    time_t    st_ctime;   /* time of last status change */
};
```

I use
[`S_ISREG`](https://www.gnu.org/software/libc/manual/html_node/Testing-File-Type.html#index-S_005fISREG):
to check if the handled is a regular file. After mmapping with the size stored
in `stat.st_size` I do a bookkeeping, see the combined snippet below:

```c
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "io.h"

Str IO_read_file_to_string(char *path) {
  ASSERT(path != NULL, "path was NULL");

  int fd = open(path, O_RDONLY);
  ASSERT(fd != -1, "failed to open input file");

  struct stat s;
  fstat(fd, &s);
  ASSERT(S_ISREG(s.st_mode), "path is not a file");

  long length = s.st_size;
  if (length < 0) {
    close(fd);
    ASSERT(length > 0, "input is empty")
  }

  char *buffer = 0;
  if (length != 0) {
    buffer = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
  }

  ASSERT(close(fd) == 0, "failed to close file");
  ASSERT(buffer != MAP_FAILED, "failed to mmap input")
  return (Str){.len = length, .p = (const uint8_t *)buffer};
}
```

{{<callout type="Info - Benchmarks">}}
In my benchmark this made the stage before even starting lexing 6x-35x
faster, see
[`a2cae88`](https://github.com/xNaCly/purple-garden/commit/a2cae881e8d1668d82b918b2554465c0f510e3e0):

_Please excuse the ugly debug info, I have reworked this till then. Also,
lexing and parsing was a single stage back then._

```text
io: use mmap to make IO_read_file_to_string 6x-35x faster
For 5k lines with 4 atoms each (20k atoms), the initial string read was
reduced from 0.4390ms to 0.0730ms (6x faster):

Old:
    [BENCH] (T-0.1620ms): parsed arguments
    [BENCH] (T-0.4390ms): read file to String
    [BENCH] (T-10.2020ms): parsed input
    [BENCH] (T-1.2820ms): compiled input
    [BENCH] (bc=40008|globals=20004)
    [BENCH] (T-0.1620ms): ran vm
    [BENCH] (T-0.6190ms): destroyed Nodes, vm and input

New:
    [BENCH] (T-0.1510ms): parsed arguments
    [BENCH] (T-0.0730ms): read file to String
    [BENCH] (T-10.1350ms): parsed input
    [BENCH] (T-1.3210ms): compiled input
    [BENCH] (bc=40008|globals=20004)
    [BENCH] (T-0.1710ms): ran vm
    [BENCH] (T-0.6460ms): destroyed Nodes, vm and input

For larger files, such as 250k lines with 4 atoms each (1mio atoms), the
initial string read was reduced from 3.472ms to 0.0980ms (35x faster):

Old:
    [BENCH] (T-0.1430ms): parsed arguments
    [BENCH] (T-3.4720ms): read file to String
    [BENCH] (T-434.8770ms): parsed input
    [BENCH] (T-30.7538ms): compiled input
    [BENCH] (bc=2040408|globals=1020204)
    [BENCH] (T-7.5610ms): ran vm
    [BENCH] (T-37.2170ms): destroyed Nodes, vm and input

New:
    [BENCH] (T-0.1490ms): parsed arguments
    [BENCH] (T-0.0980ms): read file to String
    [BENCH] (T-437.4770ms): parsed input
    [BENCH] (T-30.8820ms): compiled input
    [BENCH] (bc=2040408|globals=1020204)
    [BENCH] (T-7.4540ms): ran vm
    [BENCH] (T-36.9500ms): destroyed Nodes, vm and input
```

{{</callout>}}

# Consuming numeric tokens in the compiler

As introduced in [On demand double and int64_t
parsing](#on-demand-double-and-int64_t-parsing), the lexer does not perform
string to numerical conversions, but rather stores a hash and a window of said
string. The compiler converts any tokens with this hash only once and refers
any duplicates to the global pool index of this number.

> The compiler itself will probably be the topic of a future blog article, but I kept it simple at this time.

`token_to_value` is called for all unique (not encountered before and thus not interned) atoms:

```c
// token_to_value converts tokens, such as strings, idents and numbers to
// runtime values
inline static Value *token_to_value(Token *t, Allocator *a) {
  Value *v = CALL(a, request, sizeof(Value));
  switch (t->type) {
  case T_STRING:
  case T_IDENT:
    v->type = V_STR;
    v->string = t->string;
    break;
  case T_INTEGER:
    v->type = V_INT;
    v->integer = Str_to_int64_t(&t->string);
    break;
  case T_DOUBLE:
    v->type = V_DOUBLE;
    v->floating = Str_to_double(&t->string);
    break;
  default:
    ASSERT(0, "Unsupported value for token_to_value");
    break;
  }
  return v;
}
```

Note the missing cases for `T_FALSE` and `T_TRUE`? They are omitted, because
there are hard coded entries `0` and `1` in the global pool (`@None` is the
same, its bound to index `2`).

{{<callout type="Info - Benchmarks">}}
This resulted in crazy 15ms/64% faster total runtime results for number and
duplicate heavy test inputs, see
[`a55a190`](https://github.com/xNaCly/purple-garden/commit/a55a19050d0a496123a27492c5bd9c674221a322).

```text
lexer+cc: move Str_to_(double|int64_t) parsing from lexer to cc
This change omits all integer and number parsing from the pipeline but
the first occurence of each unique integer or number by storing a hash
of the string representation of said values. At the interning stage in
the compiler only the first occurence of any hash of a double or integer
is parsed via Str_to_int64_t or Str_to_double, which reduces the
theoretically workload for any duplicated number of integers and doubles
from N to 1.

For a double and integer heavy benchmark (250k loc with 250k duplicated
doubles and integers) results in:

    - 15ms faster
    - 64% faster
    - ~2.8x faster

Prev commit:
    ./build/bench +V examples/bench.garden
    [    0.0000ms] main::Args_parse: Parsed arguments
    [    0.0120ms] io::IO_read_file_to_string: mmaped input of size=2500090B
    [    0.0050ms] mem::init: Allocated memory block of size=153092096B
    [   23.8300ms] lexer::Lexer_all: lexed tokens count=1000033
    [   12.5190ms] parser::Parser_next created AST with node_count=250003
    [    9.2090ms] cc::cc: Flattened AST to byte code/global pool length=1500048/4
    [   36.3060ms] vm::Vm_run: executed byte code
    [    0.3730ms] mem::Allocator::destroy: Deallocated memory space
    [    0.0410ms] vm::Vm_destroy: teared vm down
    [    0.0000ms] munmap: unmapped input

New:
    ./build/bench +V examples/bench.garden
    [    0.0000ms] main::Args_parse: Parsed arguments
    [    0.0170ms] io::IO_read_file_to_string: mmaped input of size=2500090B
    [    0.0060ms] mem::init: Allocated memory block of size=153092096B
    [    8.5270ms] lexer::Lexer_all: lexed tokens count=1000033
    [   12.2070ms] parser::Parser_next created AST with node_count=250003
    [    9.4020ms] cc::cc: Flattened AST to byte code/global pool length=1500048/4
    [   36.9900ms] vm::Vm_run: executed byte code
    [    0.3960ms] mem::Allocator::destroy: Deallocated memory space
    [    0.0480ms] vm::Vm_destroy: teared vm down
    [    0.0010ms] munmap: unmapped input
```

{{</callout>}}

# Benchmark

So I created, what i would consider a fairly heavy lexer benchmark:

```scheme
(@Some (@Some (@Some (@None))))
true false true false
3.1415 22222222222 .12345
"string me this, string me that"
'quoted-strings-is-a-must-do
(@let unquoted-strings-are-just-idents (@None))
unquoted-strings-are-just-idents
(@None) (+) (-) (*) (/) (=)
;; COMMENT COMMENT COMMENT
;; COMMENT COMMENT COMMENT
;; COMMENT COMMENT COMMENT with whitespace for 3 lines



;; whitespace end
```

And I typed `VggyG66666p` to fill 1mio lines (`1000005`).

## On a Laptop

{{<shellout>}}
$ inxi -CMD
%SEPARATOR%
System:
  Host: ************* Kernel: 6.11.0-28-generic arch: x86_64 bits: 64
  Desktop: i3 v: 4.23 Distro: Ubuntu 24.04.2 LTS (Noble Numbat)
Machine:
  Type: Laptop System: LENOVO product: 21F8002TGE v: ThinkPad T14s Gen 4
    serial: <superuser required>
  Mobo: LENOVO model: 21F8002TGE v: SDK0T76530 WIN
    serial: <superuser required> UEFI: LENOVO v: R2EET41W (1.22 )
    date: 09/22/2024
CPU:
  Info: 8-core model: AMD Ryzen 7 PRO 7840U w/ Radeon 780M Graphics bits: 64
    type: MT MCP cache: L2: 8 MiB
  Speed (MHz): avg: 883 min/max: 400/5132 cores: 1: 1388 2: 400 3: 1396
    4: 400 5: 400 6: 400 7: 1374 8: 400 9: 1331 10: 400 11: 1357 12: 400
    13: 1357 14: 1346 15: 1393 16: 400
{{</shellout>}}

With the above components.

{{<shellout>}}
$ make bench
%SEPARATOR%
./build/bench +V examples/bench.garden
[    0.0000ms] main::Args_parse: Parsed arguments
[    0.0150ms] io::IO_read_file_to_string: mmaped input of size=25466794B
[    0.0060ms] mem::init: Allocated memory block of size=929537981B
[   43.9190ms] lexer::Lexer_all: lexed tokens count=3133350
[   48.8460ms] parser::Parser_next created AST with node_count=1200006
[   18.2070ms] cc::cc: Flattened AST to byte code/global pool length=2666680/8
[    8.9970ms] vm::Vm_run: executed byte code
[   26.7470ms] mem::Allocator::destroy: Deallocated memory space
[    1.0180ms] vm::Vm_destroy: teared vm down
[    0.0000ms] munmap: unmapped input
{{</shellout>}}

I can confidently say I do a million lines or 25,466,794 Bytes in 44ms. Let's do some math:

$$
\begin{align}
44 \textrm{ms} &\triangleq 25,466,749 \mathrm{B} \\
1 \textrm{ms} &\triangleq 578,789.75 \mathrm{B} \\
1000 \textrm{ms} &\triangleq 578,789,750 \mathrm{B} \\
&= \underline{578,79 \mathrm{MB}/\textrm{s}}
\end{align}
$$

In token:

$$
\begin{align}
44 \textrm{ms} &\triangleq 3,133,350 \mathrm{T} \\
1 \textrm{ms} &\triangleq 71212.5 \mathrm{T} \\
1000 \textrm{ms} &\triangleq 71,212,500 \mathrm{T} \\
&= \underline{71,212,500 \mathrm{T}/\textrm{s}}
\end{align}
$$

That's pretty fast, but SIMD can probably do a lot better at this point.
However, I haven't started that experiment yet.

## On a Tower

{{<shellout>}}
$ inxi -CMD
%SEPARATOR%
System:
  Host: comfyputer Kernel: 6.15.4-arch2-1 arch: x86_64
    bits: 64
  Desktop: i3 v: 4.24 Distro: Arch Linux
Machine:
  Type: Desktop Mobo: ASUSTeK model: PRIME B450-PLUS
    v: Rev X.0x serial: <superuser required>
    UEFI: American Megatrends v: 2008 date: 12/06/2019
CPU:
  Info: 8-core model: AMD Ryzen 7 3700X bits: 64
    type: MT MCP cache: L2: 4 MiB
  Speed (MHz): avg: 4052 min/max: 2200/4979 cores:
    1: 4052 2: 4052 3: 4052 4: 4052 5: 4052 6: 4052
    7: 4052 8: 4052 9: 4052 10: 4052 11: 4052 12: 4052
    13: 4052 14: 4052 15: 4052 16: 4052
{{</shellout>}}

So we are around 14ms faster on my tower.

```text
./build/bench +V examples/bench.garden
[    0.0000ms] main::Args_parse: Parsed arguments
[    0.0070ms] io::IO_read_file_to_string: mmaped input of size=25400127B
[    0.0030ms] mem::init: Allocated memory block of size=927104635B
[   30.9930ms] lexer::Lexer_all: lexed tokens count=3133350
[   22.6340ms] parser::Parser_next created AST with node_count=1200006
[   10.1480ms] cc::cc: Flattened AST to byte code/global pool length=2666680/8
[    7.4800ms] vm::Vm_run: executed byte code
[    0.7520ms] mem::Allocator::destroy: Deallocated memory space
[    0.0620ms] vm::Vm_destroy: teared vm down
[    0.0000ms] munmap: unmapped input
```

The same math as above, just with 30ms instead of 44ms:

$$
\begin{align}
30 \textrm{ms} &\triangleq 25,466,749 \mathrm{B} \\
1 \textrm{ms} &\triangleq 848,891.633333 \mathrm{B} \\
1000 \textrm{ms} &\triangleq 848,891,633.333 \mathrm{B} \\
&= \underline{848.89 \mathrm{MB}/\textrm{s}}
\end{align}
$$

In token:

$$
\begin{align}
30 \textrm{ms} &\triangleq 3,133,350 \mathrm{T} \\
1 \textrm{ms} &\triangleq 104,445 \mathrm{T} \\
1000 \textrm{ms} &\triangleq 104,445,000 \mathrm{T} \\
&= \underline{104,445,000 \mathrm{T}/\textrm{s}}
\end{align}
$$

## Benchmark contexts

For a C input of 7.5 mio loc, which is of course more complex to tokenize then
my language, see [_Some Strategies For Fast Lexical Analysis when Parsing
Programming Languages_](https://nothings.org/computer/lexing.html). The
following numbers are available and I added the performance the purple-garden
lexer has for 7.5mio lines lexer heavy benchmark inputs.

| lexer                      | performance |
| -------------------------- | ----------- |
| flex (default)             | 13.56 s     |
| stb_lex (w/symbol hashing) | 4.84 s      |
| stb_lex                    | 4.23 s      |
| flex -F (fast)             | 3.07 s      |
| flex -f (full)             | 2.92 s      |
| handcoded                  | 2.45 s      |
| handcoded mmap             | 2.14 s      |
| wc                         | 1.73 s      |
|                            |             |
| purple-garden (laptop)     | 0.308s      |
| purple-garden (tower)     | 0.150s      |

# What next

A summary what I implemented in this article:

- Jump table for direct threading
- 0 copy and window based tokens
- interned and stateless tokens
- bump allocator for unique tokens
- inline hashing for atoms that need it (strings, idents, numeric)
- fast paths for true and false

While 580-848 MB/s is already pretty fast, I want to go further, some things I have planned:

- use the absurd bit set based `is_alphanum` checks
- use SIMD for comments and whitespace
- use SIMD as a preprocessing step to find markers for tokens 16 bytes at a time
- replace FNV-1a with a faster hashing algorithm, something like [xxHash](https://xxhash.com/)
- prefetch some amount of bytes to reduce L1 & L2 latency
- mmap larger inputs with `MAP_HUGETLB`
- maybe align mmap to 64 byte boundaries for SIMD


# Putting it all together

```c
#include "lexer.h"
#include "common.h"
#include "mem.h"
#include "strings.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define SINGLE_TOK(t) ((Token){.type = t})

Str TOKEN_TYPE_MAP[] = {[T_DELIMITOR_LEFT] = STRING("T_DELIMITOR_LEFT"),
                        [T_DELIMITOR_RIGHT] = STRING("T_DELIMITOR_RIGHT"),
                        [T_BRAKET_LEFT] = STRING("T_BRAKET_LEFT"),
                        [T_BRAKET_RIGHT] = STRING("T_BRAKET_RIGHT"),
                        [T_STRING] = STRING("T_STRING"),
                        [T_TRUE] = STRING("T_TRUE"),
                        [T_FALSE] = STRING("T_FALSE"),
                        [T_DOUBLE] = STRING("T_DOUBLE"),
                        [T_INTEGER] = STRING("T_INTEGER"),
                        [T_BUILTIN] = STRING("T_BUILTIN"),
                        [T_IDENT] = STRING("T_IDENT"),
                        [T_PLUS] = STRING("T_PLUS"),
                        [T_MINUS] = STRING("T_MINUS"),
                        [T_ASTERISKS] = STRING("T_ASTERISKS"),
                        [T_SLASH] = STRING("T_SLASH"),
                        [T_EQUAL] = STRING("T_EQUAL"),
                        [T_EOF] = STRING("T_EOF")};

Lexer Lexer_new(Str input) {
  return (Lexer){
      .input = input,
      .pos = 0,
  };
}

#define cur(L) (L->input.p[L->pos])

__attribute__((always_inline)) inline static bool is_alphanum(uint8_t cc) {
  uint8_t lower = cc | 0x20;
  bool is_alpha = (lower >= 'a' && lower <= 'z');
  bool is_digit = (cc >= '0' && cc <= '9');
  return is_alpha || is_digit || cc == '_' || cc == '-';
}

// we can "intern" these, since all of them are the same, regardless of position
Token *INTERN_DELIMITOR_LEFT = &SINGLE_TOK(T_DELIMITOR_LEFT);
Token *INTERN_DELIMITOR_RIGHT = &SINGLE_TOK(T_DELIMITOR_RIGHT);
Token *INTERN_BRAKET_LEFT = &SINGLE_TOK(T_BRAKET_LEFT);
Token *INTERN_BRAKET_RIGHT = &SINGLE_TOK(T_BRAKET_RIGHT);
Token *INTERN_MINUS = &SINGLE_TOK(T_MINUS);
Token *INTERN_PLUS = &SINGLE_TOK(T_PLUS);
Token *INTERN_ASTERISKS = &SINGLE_TOK(T_ASTERISKS);
Token *INTERN_SLASH = &SINGLE_TOK(T_SLASH);
Token *INTERN_FALSE = &SINGLE_TOK(T_FALSE);
Token *INTERN_TRUE = &SINGLE_TOK(T_TRUE);
Token *INTERN_EQUAL = &SINGLE_TOK(T_EQUAL);
Token *INTERN_EOF = &SINGLE_TOK(T_EOF);

size_t Lexer_all(Lexer *l, Allocator *a, Token **out) {
  ASSERT(out != NULL, "Failed to allocate token list");

  // empty input
  if (l->input.len == 0) {
    out[0] = INTERN_EOF;
    return 1;
  }

  size_t true_hash = Str_hash(&STRING("true"));
  size_t false_hash = Str_hash(&STRING("false"));

  size_t count = 0;
  static void *jump_table[256] = {
      [0 ... 255] = &&unknown,
      [' '] = &&whitespace,
      ['\t'] = &&whitespace,
      ['\n'] = &&whitespace,
      [';'] = &&comment,
      ['('] = &&delimitor_left,
      [')'] = &&delimitor_right,
      ['@'] = &&builtin,
      ['.'] = &&number,
      ['0' ... '9'] = &&number,
      ['a' ... 'z'] = &&ident,
      ['A' ... 'Z'] = &&ident,
      ['_'] = &&ident,
      ['\''] = &&quoted,
      ['"'] = &&string,
      ['+'] = &&plus,
      ['-'] = &&minus,
      ['/'] = &&slash,
      ['*'] = &&asterisk,
      ['='] = &&equal,
      ['['] = &&bracket_left,
      [']'] = &&bracket_right,
      [0] = &&end,
  };

#define JUMP_TARGET goto *jump_table[(int32_t)l->input.p[l->pos]]

  JUMP_TARGET;

delimitor_left:
  out[count++] = INTERN_DELIMITOR_LEFT;
  l->pos++;
  JUMP_TARGET;

delimitor_right:
  out[count++] = INTERN_DELIMITOR_RIGHT;
  l->pos++;
  JUMP_TARGET;

bracket_left:
  out[count++] = INTERN_BRAKET_LEFT;
  l->pos++;
  JUMP_TARGET;

bracket_right:
  out[count++] = INTERN_BRAKET_RIGHT;
  l->pos++;
  JUMP_TARGET;

builtin: {
  l->pos++;
  // not an ident after @, this is shit
  if (!is_alphanum(cur(l))) {
    out[count++] = INTERN_EOF;
  }
  size_t start = l->pos;
  size_t hash = FNV_OFFSET_BASIS;
  for (char cc = cur(l); cc > 0 && is_alphanum(cc); l->pos++, cc = cur(l)) {
    hash ^= cc;
    hash *= FNV_PRIME;
  }

  size_t len = l->pos - start;
  Str s = (Str){
      .p = l->input.p + start,
      .len = len,
      .hash = hash,
  };
  Token *b = CALL(a, request, sizeof(Token));
  b->string = s;
  b->type = T_BUILTIN;
  out[count++] = b;
  JUMP_TARGET;
}

plus:
  out[count++] = INTERN_PLUS;
  l->pos++;
  JUMP_TARGET;

minus:
  out[count++] = INTERN_MINUS;
  l->pos++;
  JUMP_TARGET;

slash:
  out[count++] = INTERN_SLASH;
  l->pos++;
  JUMP_TARGET;

equal:
  out[count++] = INTERN_EQUAL;
  l->pos++;
  JUMP_TARGET;

asterisk:
  out[count++] = INTERN_ASTERISKS;
  l->pos++;
  JUMP_TARGET;

number: {
  size_t start = l->pos;
  size_t i = start;
  bool is_double = false;
  size_t hash = FNV_OFFSET_BASIS;
  for (; i < l->input.len; i++) {
    char cc = l->input.p[i];
    hash ^= cc;
    hash *= FNV_PRIME;
    if (cc >= '0' && cc <= '9')
      continue;
    if (cc == '.') {
      ASSERT(!is_double, "Two dots in double");
      is_double = true;
      continue;
    }
    break;
  }

  l->pos = i;
  Token *n = CALL(a, request, sizeof(Token));
  n->string = (Str){
      .p = l->input.p + start,
      .len = i - start,
      .hash = hash,
  };
  if (is_double) {
    n->type = T_DOUBLE;
  } else {
    n->type = T_INTEGER;
  }

  out[count++] = n;
  JUMP_TARGET;
}

ident: {
  size_t start = l->pos;
  size_t hash = FNV_OFFSET_BASIS;
  for (char cc = cur(l); cc > 0 && is_alphanum(cc); l->pos++, cc = cur(l)) {
    hash ^= cc;
    hash *= FNV_PRIME;
  }

  size_t len = l->pos - start;
  Token *t;
  if (hash == true_hash) {
    t = INTERN_TRUE;
  } else if (hash == false_hash) {
    t = INTERN_FALSE;
  } else {
    t = CALL(a, request, sizeof(Token));
    t->type = T_IDENT;
    t->string = (Str){
        .p = l->input.p + start,
        .len = len,
        .hash = hash,
    };
  }
  out[count++] = t;
  JUMP_TARGET;
}

// same as string but only with leading '
quoted: {
  // skip '
  l->pos++;
  size_t start = l->pos;
  size_t hash = FNV_OFFSET_BASIS;
  for (char cc = cur(l); cc > 0 && is_alphanum(cc); l->pos++, cc = cur(l)) {
    hash ^= cc;
    hash *= FNV_PRIME;
  }

  size_t len = l->pos - start;
  Token *t;
  t = CALL(a, request, sizeof(Token));
  t->type = T_STRING;
  t->string = (Str){
      .p = l->input.p + start,
      .len = len,
      .hash = hash,
  };
  out[count++] = t;
  JUMP_TARGET;
}

string: {
  // skip "
  l->pos++;
  size_t start = l->pos;
  size_t hash = FNV_OFFSET_BASIS;
  for (char cc = cur(l); cc > 0 && cc != '"'; l->pos++, cc = cur(l)) {
    hash ^= cc;
    hash *= FNV_PRIME;
  }

  if (UNLIKELY(cur(l) != '"')) {
    Str slice = Str_slice(&l->input, l->pos, l->input.len);
    fprintf(stderr, "lex: Unterminated string near: '%.*s'", (int)slice.len,
            slice.p);
    out[count++] = INTERN_EOF;
  } else {
    Token *t = CALL(a, request, sizeof(Token));
    t->type = T_STRING;
    t->string = (Str){
        .p = l->input.p + start,
        .len = l->pos - start,
        .hash = hash,
    };
    out[count++] = t;
    // skip "
    l->pos++;
  }
  JUMP_TARGET;
}

comment:
  for (char cc = cur(l); cc > 0 && cc != '\n'; l->pos++, cc = cur(l)) {
  }
  JUMP_TARGET;

whitespace:
  l->pos++;
  JUMP_TARGET;

unknown: {
  uint8_t c = cur(l);
  ASSERT(0, "Unexpected byte '%c' (0x%X) in input", c, c)
}

end:
  out[count++] = INTERN_EOF;
  return count;
}

#undef SINGLE_TOK
```

Thank you for reading this far. If you have any suggestions or feedback, feel
free to send me an email at [contact@xnacly.me](mailto:contact@xnacly.me) or:

> `contact@xnacly.me`
