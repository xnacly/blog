---
title: "Hybrid Register/Stack VM for Faster Function Calls"
summary: " Designing a calling convention by merging registers and a stack into the purple-garden vm"
date: 2025-06-01
tags:
  - c
  - pldev
---

I'm building another programming language -
[purple-garden](http://github.com/xnacly/purple-garden) - this time less lispy,
but still s-expr based. It's not inherently functional, but has pure
functions. I wanted to make a fast programming language that's fun to implement
and fun (for me) to program in. So far, this is the result.

Some virtual machines are stack based and implement function calls via this
approach, others are using registers for all function arguments. I decided to
go with a hybrid approach and use registers for function calls with a single
argument and a stack for functions with n>1 arguments. This will hopefully
allow me to keep the vm impl simple, optimize for the common case of a single
argument and use the least amount of instructions possible.

# VM Architecture, Bytecode and Disassembly

Since some consider programming languages, and implementing one modern day
magic, I'll introduce some basic concepts while going over the architecture of
purple gardens interpretation pipeline.

`(@println "Hello World")` or `(* 3.1415 (* 1.5 1.5))` for a bytecode
interpeter, would generally pass through the following stages:

1. Tokenisation
2. Parsing
3. Compiling to Bytecode
4. Executing Bytecode

For instance `(* 3.1415 (* 1.5 1.5))`:

## 1. Tokenisation

```text
[T_DELIMITOR_LEFT]
[T_ASTERISKS]
[T_DOUBLE](3.1415)
[T_DELIMITOR_LEFT]
[T_ASTERISKS]
[T_DOUBLE](1.5)
[T_DOUBLE](1.5)
[T_DELIMITOR_RIGHT]
[T_DELIMITOR_RIGHT]
[T_EOF]
```

Tokenisation refers to - as the name implies, splitting the input up into
tokens with meaning. In purple garden a token is simply a tagged value
container. Generally it would also hold data related to its source
location, like a line and a column.

```c
typedef enum {
  // (
  T_DELIMITOR_LEFT = 1,
  // assigned OP numbers because we directly map these in the compiler, see
  // vm.h#VM_OP
  T_PLUS = 2,
  T_MINUS = 3,
  T_ASTERISKS = 4,
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
  T_TRUE,
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
  union {
    // filled when .type=T_STRING|T_IDENT
    Str string;
    // filled when .type=T_DOUBLE
    double floating;
    // filled when .type=T_INTEGER
    int64_t integer;
  };
} Token;
```

## 2. Parsing

The parser uses the tokens produced by the tokenizer to build an abstract
syntax tree (AST):

```text
N_BIN[T_ASTERISKS](
 N_ATOM[T_DOUBLE](3.1415),
 N_BIN[T_ASTERISKS](
  N_ATOM[T_DOUBLE](1.5),
  N_ATOM[T_DOUBLE](1.5)
 )
)
```

Now we know:

- the precedence of the s-expr: 1.5*1.5 needs to be executed before multiplying the result with 3.1415
- how many elements to apply which s-expr to
- what element belongs to what s-expr

## 3. Compiling to Bytecode

Bytecode is generally defined as a list of operators and their respective
arguments encoded as bytes.

Since this vm is registerbased, the bytecode operates on the accumulator
register (`r0`) and its operand. The compiler emits bytecode for nodes of the
AST from bottom to top:

### Atoms

```
  N_ATOM[T_DOUBLE](1.5)
```

Compiles to:

```asm
; load value at index 3 of global pool into r0
LOAD 3
```

Where the argument `3` refers to the index into the global pool at which
`Double(1.5)` is stored at.

### "Binary" operators

```text
 N_BIN[T_ASTERISKS](
  N_ATOM[T_DOUBLE](1.5),
  N_ATOM[T_DOUBLE](1.5)
 )
```

The atoms parts will be compiled as explained above, the only change is moving
the temporary value needed for addition into another register:

```asm
; load value at index 3 of global pool into r0
LOAD  3
; move value in r0 into r1
STORE 1
; load value at index 4 of global pool into r0
LOAD  4
```

The multiplication itself is done by `MUL`. Lhs is assumed to be r0, rhs is the
argument passed to the opcode:

```asm
; load value at index 3 of global pool into r0
LOAD  3
; move value in r0 into r1
STORE 1
; load value at index 4 of global pool into r0
LOAD  4
; muliply r0 and r1
MUL   1
```

This means the first multiplication s-expr `(* 1.5 1.5)` compiles to the above
and leaves the result in the accumulator register r0. Applying this to the root s-expr, we get:

```asm
; (* 1.5 1.5)
    ; 1.5
    LOAD  3
    ; r0->r1
    STORE 1
    ; 1.5
    LOAD  4
    ; r0*r1
    MUL   1

; (* 3.1415 r0)
    ; r0->r1
    STORE 1
    ; 3.1415
    LOAD  5
    ; r0*r1
    MUL   1
```

## 4. Executing Bytecode

At a high level the bytecode virtual machine:

1. indexes into bytecode array at `vm->pc` (program counter) for the current op code
2. indexes into bytecode array at `vm->pc+1` for the current argument
3. execute corresponding logic for the opcode and manipulate registers or other internal state

# Bytecode overview and some decisions


The whole pipeline uses a two byte tuple: `OP` and `ARG`, this keeps the
fetching, decoding and emitting lean + fast.

Since there may be some not obvious instruction meanings, here's a
table:

| Opcode / Instruction      | Description                                                            |
| ------------------------- | ---------------------------------------------------------------------- |
| `STORE <reg>`             | Moves the contents of `r0` to `reg`                                    |
| `ARGS <amount>`           | Instructs the vm to expect `amount` of arguments to calls and builtins |
| `LEAVE `                  | Leaves a scope                                                         |
| `LOAD <global pool idx> ` | Loads a global into `r0`                                               |
| `BUILTIN <hash> `         | Calls a builtin by the hash of its name                                |
| `CALL <hash> `            | Calls a function by the hash of its name                               |
| `VAR <reg> `              | Creates a variable by its name in `r0` and its value in `reg`          |
| `LOADV <hash> `           | Loads a variable by its hash from the variable table into `r0`         |
| `POP`                     | Pops a value from the stack into `r0`                                  |
| `PUSH`                    | Pushes `r0` to the stack                                               |
| `PUSHG <global pool idx>` | Pushes a global to the stack                                           |

`PUSHG` is an optimisation to merge `LOAD` and `PUSH`, which is a common
pattern in function calling setup...

# Calling and defining Functions

Since every good language needs a way to structure and reuse code, purple
garden (pg) needs functions.

```scheme
; (@function <name> [<list of arguments>] <s-expr body>)
(@function no-args [] (@None))
(@function one-arg [a] (@Some a))
(@function two-args [a b] (@Some a))
(@function three-args [a b c] (@Some a))
(@function four-args [a b c d] (@Some a))
; ...
```

And we just call them in the

```scheme
(no-args)
(one-arg 1)
(two-args 1 2)
(three-args 1 2 3)
(four-args 1 2 3 4)
```

# Generating Definition Bytecode

Once a function is defined the compiler emits bytecode for said function
including its body and the setup for all params, this differs for 0, 1 and n
arguments:

## No argument

```scheme
(@function no-args [] (@None))
```

No argument, thus we can omit prep for argument passing:

```asm
__globals:
        False; {idx=0}
        True; {idx=1}
        Option(None); {idx=2}

__entry:
__0x000000[01EC]: no-args
        JMP 6
        ARGS 0
        BUILTIN 1019: <@None>
        LEAVE
```

## Single Argument

```scheme
(@function one-arg [a] (@Some a))
```

A singular argument is passed by a pointer to its value being stored in `r0`,
this makes calling functions with a single argument way faster than using the
stack based method for enabling n arguments:

```asm
__0x000008[02B6]: one-arg
        JMP 20
        ; function head / parameter creation
        STORE 1 ; 1. move &Value from r0 to r1
        LOAD 4: Str(`a`) ; 2. load name of variable into r0
        VAR 1   ; 3. create an entry in variable table with the hash of its name
                ; (computed at compile time) and its &Value in r1

        ; function body
        LOADV 796972: $a
        BUILTIN 145: <@Some>
        LEAVE
```

## n Arguments

```scheme
(@function three-args [a b c] (@Some a))
```

This is where the mix of registers and stack is used. Since the value for the
last argument is always in `r0`. Any further arguments are stored on the stack:

```text
args: a b c
vals: 1 2 3

stack: 1 2
r0: 3
```

In the disassembled bytecode this results in simply one `POP` before comencing
with the already known argument setup:

```asm
__entry:
__0x000000[02CB]: three-args
        JMP 28

        ; function head

        ; create variable 'c' pointing to &Value
        STORE 1
        LOAD 3: Str(`c`)
        VAR 1

        ; pop &Value for variable 'b' from the stack top
        POP
        STORE 1
        LOAD 4: Str(`b`)
        VAR 1

        ; pop &Value for variable 'a' from the stack top
        POP
        STORE 1
        LOAD 5: Str(`a`)
        VAR 1

        ; function body
        LOADV 796972: $a
        BUILTIN 145: <@Some>
        LEAVE
```

# Generating Call site Bytecode

## No argument

```scheme
(@function no-args [] (@None))
(no-args)
```

Since we don't pass any arguments, the call is just the `OP_CALL` and bytecode
index for the function definition, here `0`:

```asm
__entry:
        ; ...
        CALL 0: <no-args>
```

## Single Argument

```scheme
(@function one-arg [a] (@Some a))
(one-arg 1)
```

As introduced before, a single argument can just be used from `r0`, thus the
callsite loads the global and invokes the call, no stack interaction necessary:

```asm
__entry:
        ; ...

        LOAD 4: Int(1)
        CALL 0: <one-arg>
```

## n Arguments

```scheme
(@function two-args [a b] (@Some a))
(@function three-args [a b c] (@Some a))
(@function four-args [a b c d] (@Some a))
(two-args 1 2)
(three-args 1 2 3)
(four-args 1 2 3 4)
```

Like above, the last argument is always in `r0`, thus all other arguments will
need to be on the stack. This is implemented by `PUSH` (or `PUSHG` if `LOAD`
and `PUSH` are emitted consecutively) at the callsite. For each argument except
the last, a `PUSH` is required. The instruction before `CALL` or `BUILTIN` is
`ARGS`, instructing the vm to pop the right amount of arguments of the stack.

```asm
__entry:
        ; ...

        PUSHG 7: Int(1)
        LOAD 8: Int(2)
        ARGS 2
        CALL 0: <two-args>

        PUSHG 9: Int(1)
        PUSHG 10: Int(2)
        LOAD 11: Int(3)
        ARGS 3
        CALL 22: <three-args>

        PUSHG 12: Int(1)
        PUSHG 13: Int(2)
        PUSHG 14: Int(3)
        LOAD 15: Int(4)
        ARGS 4
        CALL 52: <four-args>
```

# Benchmark

{{<callout type="Warning">}}
This is a microbenchmark done on a high noise & high load laptop system, take
everything here with a grain of salt, either way, here are the specs:

```text
System:
  Kernel: 6.11.0-24-generic arch: x86_64 bits: 64
  Desktop: i3 v: 4.23 Distro: Ubuntu 24.04.2 LTS (Noble Numbat)
Machine:
  Type: Laptop System: LENOVO product: 21F8002TGE v: ThinkPad T14s Gen 4
CPU:
  Info: 8-core model: AMD Ryzen 7 PRO 7840U w/ Radeon 780M Graphics bits: 64
    type: MT MCP cache: L2: 8 MiB
  Speed (MHz): avg: 1950 min/max: 400/5132 cores: 1: 1996 2: 1997 3: 1996
    4: 1996 5: 1996 6: 1852 7: 1848 8: 1852 9: 1852 10: 1853 11: 1996 12: 1996
    13: 1996 14: 1996 15: 1996 16: 1996
```

{{</callout>}}

TLDR: 25k function calls with builtins in each of them (~50k calls) in \~4.2ms
vm runtime, which is \~15.5% of the total runtime, it also scales very well,
for 250k function calls and 500k total calls with 13ms vm runtime.

{{<shellout lang="scheme">}}
$ head -n10 examples/bench.garden
%SEPARATOR%
(@function no-args [] (@None))
(@function one-arg [a] (@Some a))
(@function two-args [a b] (@Some a))
(@function three-args [a b c] (@Some a))
(@function four-args [a b c d] (@Some a))
(no-args)
(one-arg 1)
(two-args 1 2)
(three-args 1 2 3)
(four-args 1 2 3 4)
{{</shellout>}}

{{<shellout>}}
$ wc -l examples/bench.garden
%SEPARATOR%
25010 examples/bench.garden
{{</shellout>}}

{{<shellout>}}
$ make bench PG=examples/bench.garden
%SEPARATOR%
// [...]
[ 0.0000ms] main::Args_parse: Parsed arguments
[ 0.0360ms] io::IO_read_file_to_string: mmaped input of size=380261B
[ 0.0080ms] mem::init: Allocated memory block of size=612368384B
[ 3.8690ms] lexer::Lexer_all: lexed tokens count=125085
[ 5.1560ms] parser::Parser_next created AST with node_count=25010
[ 3.4340ms] cc::cc: Flattened AST to byte code/global pool length=180148/50017
[ 4.1530ms] vm::Vm_run: executed byte code
[ 3.7390ms] mem::Allocator::destroy: Deallocated memory space
[ 0.0000ms] vm::Vm_destroy: teared vm down
[ 0.0000ms] munmap: unmapped input
{{</shellout>}}

{{<shellout>}}
$ make release
$ hyperfine "./purple_garden examples/bench.garden"
%SEPARATOR%
Benchmark 1: ./purple_garden examples/bench.garden
  Time (mean ± σ):      27.2 ms ±   2.6 ms    [User: 9.1 ms, System: 15.6 ms]
  Range (min … max):    19.7 ms …  32.8 ms    93 runs
{{</shellout>}}
