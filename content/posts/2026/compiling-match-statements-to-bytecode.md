---
title: "Compiling Match Statements to Bytecode"
summary: "Full pipeline deep dive for purple garden: AST, BB SSA IR, Bytecode, Optimisations"
date: 2026-02-26T15:13:56+01:00
math: true
tags:
- rust
- pldev
---

I like Gos headless switch statements as a replacement for if-if-else-else
chains:

```go
import ("time"; "fmt")
t := time.Now()
switch {
case t.Hour() < 12:
    fmt.Println("Good morning!")
case t.Hour() < 17:
    fmt.Println("Good afternoon.")
default:
    fmt.Println("Good evening.")
}
```

So i decided purple garden will have these as the singular control structure,
for instance the above would be the following:

```python
import ("time" "io")
let t = time.now()
let greeting = match {
    t.hour() < 12 { "morning" }
    t.hour() < 17 { "afternoon" }
    { "evening" }
}
io.println("Good" greeting)
```


# Match statments

Below is the easiest and most useless match statement there is, for converting
a boolean to its integer representation:

```python
match {
    true { 1 }
    { 0 }
}
```

The general format is a conditional case evaluating to a boolean and a body.
All bodies must resolve to the same type and a default branch is required.

# Pipeline Architecture

Purple gardens architecture revolves around an intermediate representation
based on a list of functions holding a list of blocks. Each block has a list of
inputs params, a list of instructions and a singular terminator. Said
instructions are SSA based and the blocks containing them are basic blocks,
meaning each value is defined immutability and exactly once. This also means
params to blocks and params in terminators are explicit (this enables ommission
of phi nodes).

The IR sits in the intersection of the abstract syntax tree produced by parsing
the tokenized input and the three backends (currently only the bytecode backend
targeting the typed register based virtula machine is implemented). This
architecture enables decoupled codegen and a list of optimisations.

# Parsing

Parsing consumes the tokens produced by the lexical analysis / tokenisation and
builds a tree representing the source code as a concept.

```rust
// as called in main()
let mut lexer = Lexer::new(&input);
let ast = match Parser::new(&mut lexer).and_then(|n| n.parse()) {
    Ok(a) => a,
    Err(e) => {
        let lines = str::from_utf8(&input)
            .unwrap()
            .lines()
            .collect::<Vec<&str>>();
        e.render(&lines);
        std::process::exit(1);
    }
};
```

As shown in the intro, the match stmt follows the following format:

```text
match {
    <cond> { <body> }
    { <default> }
}

Expr      ::= ...
Block     ::= "{" Expr "}"
MatchStmt ::= "match" "{" (Expr Block)+ Block "}
```

Pg uses a combination of recursive descent and pratt parsing. I will focus on
the former here, since the latter doesnt apply.

```text
match   + Parser::parser
match    \_ Parser::parser
match     \_ Parser::parse_prefix
match      \_ Parser::parse_match
True       |\_ Parser::parse_expr
           | |
I("1")     |  \_ Parser::parse_prefix
I("1")     |   \_ Parser::parse_expr
           |
I("0")      \_ Parser::parse_prefix
I("0")       \_ Parser::parse_expr
```

As shown above, the call stack for our example shows all function calls
necessary to build the abstract syntax tree:

```lisp
(match
 (True I("1"))
 (I("0"))
)
```

Below I included the implementation of `Parser::parse_match`:

```rust
    fn parse_match(&mut self) -> Result<Node<'p>, PgError> {
        self.next()?;
        let mut cases = vec![];
        let mut default = None;
        let tok = self.cur().clone();

        self.expect(Type::CurlyLeft)?;
        while self.cur().t != Type::CurlyRight {
            /// default case
            if self.cur().t == Type::CurlyLeft {
                let default_token = self.cur().clone();
                self.expect(Type::CurlyLeft);
                let mut default_body = vec![];
                while self.cur().t != Type::CurlyRight {
                    default_body.push(self.parse_prefix()?);
                }
                self.expect(Type::CurlyRight);
                default = Some((default_token, default_body));
            } else {
                let condition_token = self.cur().clone();
                let condition = self.parse_expr(0)?;
                self.expect(Type::CurlyLeft);
                let mut body = vec![];
                while self.cur().t != Type::CurlyRight {
                    body.push(self.parse_prefix()?);
                }
                self.expect(Type::CurlyRight);
                cases.push(((condition_token, condition), body));
            }
        }
        self.expect(Type::CurlyRight)?;

        let Some(default) = default else {
            return Err(PgError::with_msg(
                "Missing match default branch",
                "A match statement requires a default branch",
                &tok,
            ));
        };

        Ok(Node::Match {
            id: self.next_id(),
            cases,
            default,
        })
    }
```

# Typechecking

```rust
// just before lowering to IR in Lower::ir_from 
let mut typechecker = typecheck::Typechecker::new();
for node in ast {
    let t = typechecker.node(node)?;
    crate::trace!("{} resolved to {:?}", &node, t);
}
self.types = typechecker.finalise();
```

The purple garden type system is primitive, non-generic and based on equality.
This design enables a single pass type checker with a very simple environment
and an even simpler caching of already computed types.

For a match statment, the typechecker:

1. Makes sure all conditions resolve to a `bool`
2. Makes sure all branches evaluates to the same type
3. This type is then recorded as the canonical type for this match statment

Thus in a tracing build, the typechecker prints:

```text
[34.475µs] (match
 (
  True
  I("1")
 )
 (
  I("0")
 )
)
 resolved to Int
[59.101µs] Finished type checking
```

Not conforming to the previously layed out constraints results in a pretty
printed error diagnostic:

```text
-> err: Non bool match condition
   Match conditions must be Bool, got Int instead

008 | match {
009 |     5 { 1 }
            ~ here
010 |     { 0 }
```

Not only for non bool conditions, but also for differing types in different
branches:

```text
-> err: Incompatible match case return type
   Match cases must resolve to the same type, but got Int and Bool

008 | match {
009 |     true { false }
               ~ here
010 |     { 5 }
```

The implementation is as easy as it sounds, it follows the steps mentioned
before.

```rust
Node::Match { id, cases, default } => {
    // short circuit for empty matches
    if cases.is_empty() {
        return Ok(Type::Void);
    }

    let case_count = cases.len();

    let mut branch_types: Vec<Option<(&Token, Type)>> =
        vec![const { None }; case_count];

    // 1. 
    for (i, ((condition_token, condition), body)) in cases.iter().enumerate() {
        let condition_type: Type = self.node(condition)?;

        // 1. check for condition
        if condition_type != Type::Bool {
            return Err(PgError::with_msg(
                "Non bool match condition",
                format!(
                    "Match conditions must be Bool, got {} instead",
                    condition_type
                ),
                condition_token,
            ));
        }

        // 2. collect type of the body
        let branch_return_type = self.block_type(body)?;
        branch_types[i] = Some((condition_token, branch_return_type));
    }

    // 2. canonical type is the type the default body resolves to
    let first_type = self.block_type(&default.1)?;

    // 2. check the types are all the same
    for cur in &branch_types {
        let Some((tok, ty)) = cur else { unreachable!() };

        if ty != &first_type {
            return Err(PgError::with_msg(
                "Incompatible match case return type",
                format!(
                    "Match cases must resolve to the same type, but got {} and {}",
                    first_type, ty
                ),
                *tok,
            ));
        };
    }

    // 3. record the resulting type
    self.map.insert(*id, first_type.clone());

    // 3. propagate to the caller
    first_type
}
```

# Lowering to BB SSA IR

```rust
// as called in main()
let lower = ir::lower::Lower::new();
let mut ir = match lower.ir_from(&ast) {
    Ok(ir) => ir,
    Err(e) => {
        let lines = str::from_utf8(&input)
            .unwrap()
            .lines()
            .collect::<Vec<&str>>();
        e.render(&lines);
        std::process::exit(1);
    }
};
```


The intermediate representation, as introduced in [Pipeline
Architecture](#pipeline-architecture), is based on basic blocks and static
single assignment. This means control flow is made up of blocks with lists of
instructions and are terminated explicitly. Those instructions are, again, ssa
based. This means every instruction produces exactly a single operation and is
only defined once. 

In rust type terms, this represents as:

```rust
pub struct Block<'b> {
    // [...]
    pub id: Id,
    pub instructions: Vec<Instr<'b>>,
    pub params: Vec<Id>,
    pub term: Option<Terminator>,
}

pub struct Func<'f> {
    pub name: &'f str,
    pub id: Id,
    pub ret: Option<Type>,
    pub blocks: Vec<Block<'f>>,
}
```

Thus in a human readable sense we get:

```text
// entry
fn f0() -> void {
b0():
b1():
        %v0:Bool = true
        br %v0, b2(), b3()
b2():
        %v1:Int = 1
        jmp b4(%v1)
b3():
        %v2:Int = 0
        jmp b4(%v2)
b4(%v2):
}
```

Lowering the AST to the IR requires allocation a list of blocks for each
condition (`b1`), and a list of blocks for each body (`b2`), including the
default body (`b3`). It also requires a joining block (`b4`).

Each condition is lowered into its block and each body as well. All conditions
followed by another condition are terminated by a `Terminator::Branch` jumping
conditionally to its body or to the next condition. All bodies are terminated
by `Terminator::Jump` to jump to the joining block:

```rust
pub struct Lower<'lower> {
    functions: Vec<Func<'lower>>,
    /// current function
    func: Func<'lower>,
    /// current block
    block: Id,
    id_store: IdStore,
    /// maps ast variable names to ssa values
    env: HashMap<&'lower str, Id>,
    func_name_to_id: HashMap<&'lower str, Id>,
    types: HashMap<usize, ptype::Type>,
}

impl<'lower> Lower<'lower> {
    // [...]

    fn lower_node(&mut self, node: &'lower Node) -> Result<Option<Id>, PgError> {
        Ok(match node {
            // [...]
            Node::Match { cases, default, id } => {
                let mut check_blocks = Vec::with_capacity(cases.len());
                let mut body_blocks = Vec::with_capacity(cases.len());

                // pre"allocating" bbs
                for _ in cases {
                    check_blocks.push(self.new_block());
                    body_blocks.push(self.new_block());
                }

                let params = self.cur().params.clone();

                let default_block = self.new_block();

                // the single join block, merging all value results into a single branch
                let join = self.new_block();

                for (i, ((_, condition), body)) in cases.iter().enumerate() {
                    self.switch_to_block(check_blocks[i]);
                    let Some(cond) = self.lower_node(condition)? else {
                        unreachable!(
                            "Compiler bug, match cases MUST have a condition returning a value"
                        );
                    };

                    let no_target = if i + 1 < cases.len() {
                        check_blocks[i + 1]
                    } else {
                        default_block
                    };

                    let check_block_mut = self.block_mut(check_blocks[i]);
                    check_block_mut.term = Some(Terminator::Branch {
                        cond,
                        yes: (body_blocks[i], params.clone()),
                        no: (no_target, params.clone()),
                    });
                    check_block_mut.params = params.clone();

                    self.switch_to_block(body_blocks[i]);
                    self.block_mut(body_blocks[i]).params = params.clone();
                    let mut last = None;
                    for node in body {
                        last = self.lower_node(node)?;
                    }
                    let value = last.expect("match body must produce value");

                    self.block_mut(body_blocks[i]).term = Some(Terminator::Jump {
                        id: join,
                        params: vec![value],
                    });
                }

                // the typechecker checked we have a default case, so this is safe
                let (_, body) = default;
                self.switch_to_block(default_block);
                let mut last = None;
                for node in body.iter() {
                    last = self.lower_node(node)?;
                }
                let mut default_block = self.block_mut(default_block);
                default_block.params = params;
                let last = last.expect("match default must produce value");
                default_block.term = Some(Terminator::Jump {
                    id: join,
                    params: vec![last],
                });

                self.switch_to_block(join);
                self.block_mut(join).params = vec![last];
                Some(last)
            }
        })
    }
}
```

`lower_node` is called by `Lower::ir_from`: Creating an entry point function,
creating an entry block in this function and then lowering each node
individually.

```rust
pub fn ir_from(mut self, ast: &'lower [Node]) -> Result<Vec<Func<'lower>>, PgError> {
    // [...] typechecking

    self.func = Func {
        id: Id(0),
        name: "entry",
        ret: None,
        blocks: vec![],
    };
    let entry = self.new_block();
    self.switch_to_block(entry);

    for node in ast {
        let _ = &self.lower_node(node)?;
        // reset to the main entry point block to keep emitting nodes into the correct conext
        self.switch_to_block(entry);
    }

    self.functions.push(self.func);
    Ok(self.functions)
}
```

# Lowering to Bytecode

Lowering the immediate representation to bytecode the virtual machine can
execute works on a function by function and block by block basis.

```rust
// as called in main()
let mut cc = bc::Cc::new();
if let Err(e) = cc.compile(&ir) {
    let lines = str::from_utf8(&input)
        .unwrap()
        .lines()
        .collect::<Vec<&str>>();
    e.render(&lines);
    std::process::exit(1);
};
```


We can now use the IR blocks and generate bytecode for each block.

```text
// entry
fn f0() -> void {
b0():
b1():
        %v0:Bool = true
        br %v0, b2(), b3()
b2():
        %v1:Int = 1
        jmp b4(%v1)
b3():
        %v2:Int = 0
        jmp b4(%v2)
b4(%v2):
}
```

I have annotated the resulting bytecode instruction disassembly with the
corresponding immediate representations instruction:

```asm
globals:
  0000:    true

00000000 <entry>:
; b1:
  0000:    load_global r0, 1
           ; br %v0, b2(), b3()
  0001:    jmpf r0, 3 <entry+0x3>
  0002:    jmp 6 <entry+0x6>

; b2:
           ; %v1:Int = 1
  0003:    load_imm r1, #1
           ; jmp b4(%v1)
  0004:    mov r2, r1
  0005:    jmp 8 <entry+0x8>

; b3: 
           ; %v2:Int = 0
  0006:    load_imm r2, #0
           ; jmp b4(%v1)
  0007:    jmp 8 <entry+0x8>
```

## Emitting functions and blocks

Since the IRs root construct is a function containing blocks, the bytecode
backend starts by iterating functions and blocks in functions. For each block
it then emits bytecode for instructions and bytecode for terminators.

```rust
pub struct Cc<'cc> {
    pub buf: Vec<Op>,
    pub ctx: Context<'cc>,
    /// binding a block id to its pc
    block_map: HashMap<ir::Id, u16>,
    /// prefilled block id to block
    blocks: HashMap<ir::Id, &'cc ir::Block<'cc>>,
}

impl<'cc> Cc<'cc> {
    // [...]

    fn cc(&mut self, fun: &'cc Func<'cc>) 
        -> Result<Option<reg::Reg>, PgError> {
        // [...]
        for block in &fun.blocks {
            // [...]

            for instruction in &block.instructions {
                // emit bytecode for each instruction
                self.instr(instruction);
            }

            // emit bytecode for each blocks terminator
            self.term(block.term.as_ref());
        }

        // [...]
    }
}
```

## Emitting instructions


Since in this example there is only `LoadConst` for `true`, `1` and `0`, there
is a fairly uncomplicated implementation extract for `Cc::instr`.

```rust
// purple_garden::ir

/// Compile time Value representation, used for interning and constant
/// propagation
pub enum Const<'c> {
    False,
    True,
    Int(i64),
    Double(u64),
    Str(&'c str),
}

pub struct Id(pub u32);
pub struct TypeId {
    pub id: Id,
    pub ty: Type,
}
pub enum Instr<'i> {
    // [...]
    LoadConst { dst: TypeId, value: Const<'i> },
}
```

Since `LoadConst` is fully typechecked, emitting bytecode for it is a matter of
checking if the constant is an integer and fits into `i32::MAX`, since the vm
does have a `loadimm` instruction. 

```rust
// purple_garden::bc

fn instr(&mut self, i: &ir::Instr<'cc>) {
    match i {
        ir::Instr::LoadConst { dst, value } => {
            let TypeId {
                id: ir::Id(dst), ..
            } = dst;

            match value {
                Const::Int(i) if *i < i32::MAX as i64 => {
                    self.emit(Op::LoadI {
                        dst: *dst as u8,
                        value: *i as i32,
                    });
                }
                _ => {
                    let idx = self.ctx.intern(*value);
                    self.emit(Op::LoadG {
                        dst: *dst as u8,
                        idx,
                    });
                }
            }
        }
    };
}
```

All other constants are interned via `Context::intern`. Which just makes sure
the virtual machines global pool doesnt include duplicate values.

```rust
pub struct Context<'ctx> {
    // [...]
    pub globals: HashMap<Const<'ctx>, usize>,
    pub globals_vec: Vec<Const<'ctx>>,
}

impl<'ctx> Context<'ctx> {
    pub fn intern(&mut self, constant: Const<'ctx>) -> u32 {
        if let Some(&idx) = self.globals.get(&constant) {
            return idx as u32;
        }

        let idx = self.globals_vec.len();
        if let Const::Str(str) = constant {
            let str_pool_idx = self.strings_vec.len() as i64;
            self.strings_vec.push(str);
            self.globals_vec.push(Const::Int(str_pool_idx));
        } else {
            self.globals_vec.push(constant);
        };

        self.globals.insert(constant, idx);
        idx as u32
    }
}
```

So for our instructions:

```text
%v0:Bool = true
%v1:Int = 1
%v2:Int = 0
```

Compiles to this bytecode:

```asm
load_global r0, 1
load_imm r1, #1
load_imm r2, #0
```

## Emitting terminators

Same as before, simply for another immediate representation construct:

```rust
pub enum Terminator {
    // [...]
    Jump {
        id: Id,
        params: Vec<Id>,
    },
    Branch {
        cond: Id,
        yes: (Id, Vec<Id>),
        no: (Id, Vec<Id>),
    },
}
```

This maps to bytecode as well as the instructions, but with a bit of a preamble
for the params for each.

```rust
fn term(&mut self, t: Option<&ir::Terminator>) {
    let Some(term) = t else {
        return;
    };

    match term {
        // [...]
        ir::Terminator::Jump { id, params } => {
            let target = *self.blocks.get(id).unwrap();
            for (i, param) in params.iter().enumerate() {
                let ir::Id(src) = param;
                let ir::Id(dst) = target.params[i];

                if *src == dst {
                    continue;
                }

                self.emit(Op::Mov {
                    dst: dst as u8,
                    src: *src as u8,
                });
            }

            let ir::Id(id) = id;
            self.emit(Op::Jmp { target: *id as u16 });
        }
        ir::Terminator::Branch {
            cond,
            yes: (yes, yes_params),
            no: (no, no_params),
            ..
        } => {
            let target = *self.blocks.get(yes).unwrap();
            for (i, param) in yes_params.iter().enumerate() {
                let ir::Id(src) = param;
                let ir::Id(dst) = target.params[i];

                if *src == dst {
                    continue;
                }

                self.emit(Op::Mov {
                    dst: dst as u8,
                    src: *src as u8,
                });
            }

            let ir::Id(cond) = cond;
            self.emit(Op::JmpF {
                cond: *cond as u8,
                target: yes.0 as u16,
            });

            let target = self.blocks[no];
            for (i, param) in no_params.iter().enumerate() {
                let ir::Id(src) = param;
                let ir::Id(dst) = target.params[i];

                if *src == dst {
                    continue;
                }

                self.emit(Op::Mov {
                    dst: dst as u8,
                    src: *src as u8,
                });
            }

            self.emit(Op::Jmp {
                target: no.0 as u16,
            });
        }
    }
}
```

# Real, but easy, example: factorial

[Factorial](https://en.wikipedia.org/wiki/Factorial) is easy enough to reason about, implement, and its recursive, which
is nice to debug backtracing and some other vm features:

$$
n! := \begin{cases}
1 & \textrm{if } n = 0 \\
n \cdot (n-1)! & \textrm{if } n >= 1
\end{cases}
$$

I "only" want to compute the first 20 values, since purple gardens integers are
represented as i64, so the largest fitting factorial is
`2,432,902,008,176,640,000`, corresponding to 20.

```python
fn factorial(n:int a:int) int {
    match {
        n == 0 { a }
        { factorial(n-1 n*a) }
    }
}
factorial(20 1)
```

The corresponding AST amounts to:

```lisp
(fn factorial (n:int a:int)
  (match
   ((== n 0) a)
   ((factorial (- n 1) (* n a)))))->int
(factorial 20 1)
```

Lowered to the immediate representation as:

```text
// factorial
fn f1(%v0, %v1) -> Int {
b0(%v0, %v1):
b1(%v0, %v1):
        %v2:Int = 0
        %v3:Bool = eq %v0, %v2
        br %v3, b2(%v0, %v1), b3(%v0, %v1)
b2(%v0, %v1):
        jmp b4(%v1)
b3(%v0, %v1):
        %v4:Int = 1
        %v5:Int = sub %v0, %v4
        %v6:Int = mul %v0, %v1
        %v7 = f1(%v5, %v6)
        jmp b4(%v7)
b4(%v7):
        ret %v7
}

// entry
fn f0() -> void {
b0():
        %v0:Int = 20
        %v1:Int = 1
        %v2 = f1(%v0, %v1)
}
```

Again, lowered to bytecode, results in:

```asm
00000000 <factorial>:
  0000:    load_imm r2, #0
  0001:    eq r3, r0, r2
  0002:    jmpf r3, 4 <factorial+0x2>
  0003:    jmp 6 <factorial+0x6>
  0004:    mov r7, r1
  0005:    jmp 14 <factorial+0xE>
  0006:    load_imm r4, #1
  0007:    sub r5, r0, r4
  0008:    mul r6, r0, r1
  0009:    mov r0, r5
  000a:    mov r1, r6
  000b:    call 0 <factorial>
  000c:    mov r7, r0
  000d:    jmp 14 <factorial+0xE>
  000e:    mov r0, r7
  000f:    ret

00000010 <entry>:
  0010:    load_imm r0, #20
  0011:    load_imm r1, #1
  0012:    call 0 <factorial>
  0013:    mov r2, r0
```

Adding `dbg!(vm.r[0].as_int());` to the main after `vm.run()`, shows the
correct output:

```text
[src/main.rs:265:5] vm.r[0].as_int() = 2432902008176640000
```

Compiling with release options and stuff results in a fairly quick pipeline
(~700 microseconds), but thats just a micro benchmark for a uselessly simple
function:

```text
$ hyperfine "./target/release/purple-garden f.garden" -N --warmup 10
Benchmark 1: ./target/release/purple-garden f.garden
  Time (mean ± σ):     703.6 µs ±  28.5 µs    [User: 296.2 µs, System: 354.1 µs]
  Range (min … max):   657.1 µs … 944.7 µs    3630 runs
```

# Optimisations

There are a lot of low hanging fruit in these examples (useless / noop blocks,
function call in tailcall position, unnecessary moves), this chapter glosses
over concepts, implementation and effects for some of them, for instance
`indirect_jump` and `tailcall`:

```rust
// purple_garden::opt

pub fn ir(ir: &mut [crate::ir::Func]) {
    for fun in ir {
        ir::indirect_jump(fun);
        ir::tailcall(fun);
    }
}
```

Similar to the peephole optimisations I did
[previously](https://xnacly.me/posts/2026/purple-garden-first-optimisations/),
the ir optimisations are also guarded behind `-O1`:

```rust
fn main() {
    // [...]

    if args.opt >= 1 {
        opt::ir(&mut ir);
    }

    // [...]
}
```

## Removing Useless Blocks

The `indirect_jump` optimisation removes blocks doing nothing except terminate
into another block, for instance `b2` in `factorial`:

```text
fn f1(%v0, %v1) -> Int {
b0(%v0, %v1):
b1(%v0, %v1):
        %v2:Int = 0
        %v3:Bool = eq %v0, %v2
        br %v3, b2(%v0, %v1), b3(%v0, %v1)
b2(%v0, %v1):
        jmp b4(%v1)
b3(%v0, %v1):
        %v4:Int = 1
        %v5:Int = sub %v0, %v4
        %v6:Int = mul %v0, %v1
        %v7 = f1(%v5, %v6)
        jmp b4(%v7)
b4(%v7):
        ret %v7
}
```

- `b2` has no instructions
- `b2` has an unconditional terminator
- `b2`s terminators target is another block
- `b2` is not the function entry

Thus it can be fully omited, requiring the branch terminator pointing to `b2`
to point instead to `b4`:

```diff
 b1(%v0, %v1):
         %v2:Int = 0
         %v3:Bool = eq %v0, %v2
-        br %v3, b2(%v0, %v1), b3(%v0, %v1)
+        br %v3, b4(%v1), b3(%v0, %v1)
 b2(%v0, %v1):
-        jmp b4(%v1)
+        <tombstone>
 b3(%v0, %v1):
         %v4:Int = 1
         %v5:Int = sub %v0, %v4
```

The tombstone is a marker for the codegen backends to skip generating code for
a 'dead' block and enables stable block ids, which are useful for codegen and
further optimisations on alive blocks.


```diff
// purple_garden::ir
pub struct Block<'b> {
+   /// block is dead as a result of optimisation passes
+   pub tombstone: bool,
    pub id: Id,
    pub instructions: Vec<Instr<'b>>,
    pub params: Vec<Id>,
    pub term: Option<Terminator>,
}
```

```diff
// purple_garden::bc
impl<'cc> Cc<'cc> {
    fn cc(&mut self, fun: &'cc Func<'cc>) 
        -> Result<Option<reg::Reg>, PgError> {
        // [...] prep

        for block in &fun.blocks {
+           if block.tombstone {
+               continue;
+           }

            // [...] codegen
        }
}
```

Here is where rust shines, a pretty pattern match on a blocks terminator,
extracting its targets and parameters. Pattern matching again, this time on the
edges of the terminator (fancy speak for the terminators), to check if they are
in indirect jumping positions and then rewriting either yes or no, or both if
any of the target blocks are.

```rust
pub fn indirect_jump(fun: &mut ir::Func) {
    for i in 0..fun.blocks.len() {
        let Some(ir::Terminator::Branch {
            cond,
            yes: (ir::Id(yes), yes_params),
            no: (ir::Id(no), no_params),
            ..
        }) = fun.blocks[i].term.clone()
        else {
            continue;
        };

        let yes_target = &mut fun.blocks[yes as usize];
        let yes_edge = if yes_target.instructions.is_empty() {
            if let Some(ir::Terminator::Jump { id, params }) = &yes_target.term {
                yes_target.tombstone = true;
                Some((*id, params.clone()))
            } else {
                None
            }
        } else {
            None
        };

        let no_target = &mut fun.blocks[no as usize];
        let no_edge = if no_target.instructions.is_empty() {
            if let Some(ir::Terminator::Jump { id, params }) = &no_target.term {
                no_target.tombstone = true;
                Some((*id, params.clone()))
            } else {
                None
            }
        } else {
            None
        };

        fun.blocks[i].term = Some(ir::Terminator::Branch {
            cond,
            yes: yes_edge.unwrap_or((ir::Id(yes), yes_params)),
            no: no_edge.unwrap_or((ir::Id(no), no_params)),
        });
    }
}
```

## Tail call optimisation (FUTURE)

Since factorial with an accumulator is embarrassingly
[tailcallable](https://en.wikipedia.org/wiki/Tail_call)[^1], we need a pass to
make it. 

This and the below section subject for the next blog article.

## Smarter register usage (FUTURE)

In our `factorial` example there are a few obvious cases in which instructions
could write to registers directly instead of writing to temporary registers and
moving their results to the respective register afterwards: 

```asm
  0007:    sub r5, r0, r4
  0008:    mul r6, r0, r1
  0009:    mov r0, r5
  000a:    mov r1, r6
```

And also unnecessary moves upon crossing block boundaries:

```asm
  000c:    mov r7, r0
  000d:    jmp 14 <factorial+0xE>
  000e:    mov r0, r7
```

[^1]: It even is THE example when looking into LLVMs tailcall pass: https://gist.github.com/vzyrianov/19cad1d2fdc2178c018d79ab6cd4ef10#examples
