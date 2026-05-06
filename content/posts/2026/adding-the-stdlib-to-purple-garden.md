---
title: "Engineering the Stdlib for Purple Garden"
summary: "Extending the purple-garden AST,IR,codegen and VM to support its standard library"
date: 2026-03-31
draft: true
tags:
  - rust
  - pldev
---

# Designing the stdlib 

## Scope

## Importing Packages

## Using Packages and Calling Methods

# Constraints

- Performance
- Readability
- Usability
- Trade-off between Fat and Slim standard libraries


# Setup, Documentation and Discoverability

## Registering Packages and Functions

```rust
#[derive(Debug)]
pub struct Pkg {
    pub name: &'static str,
    pub doc: &'static str,
    pub pkgs: &'static [Pkg],
    pub fns: &'static [Fn],
}

#[derive(Debug)]
pub struct Fn {
    pub name: &'static str,
    pub doc: &'static str,
    pub ptr: BuiltinFn,
    pub args: &'static [Type],
    pub ret: Type,
}

pub static STD: &[Pkg] = &[
    Pkg {
        name: "io",
        doc: "Package io provides rudimentary I/O primitives,
like writing and reading from file descriptors",
        pkgs: &[],
        fns: &[
            Fn {
                name: "println",
                doc: "writes its argument to stdout, with a newline appended",
                ptr: crate::std::io::println,
                args: &[Type::Str],
                ret: Type::Void,
            },
            Fn {
                name: "print",
                ptr: crate::std::io::print,
                doc: "writes its argument to stdout",
                args: &[Type::Str],
                ret: Type::Void,
            },
        ],
    },
    // ...
    Pkg {
        name: "test",
        doc: "Package test includes helpers for runtime assertions and the likes",
        pkgs: &[],
        fns: &[Fn {
            name: "assert",
            doc: "Asserts arg0 is true",
            ptr: crate::std::test::assert,
            args: &[Type::Bool],
            ret: Type::Void,
        }],
    },
];

/// resolve_pkg searches for a package in the standard library by its name, for instance "io/fs",
/// "runtime/gc" or "encoding/json"
pub fn resolve_pkg(query: &str) -> Option<&Pkg> {
    let mut segments = query.split('/');

    let first = segments.next()?;
    let root = STD.iter().find(|p| p.name == first)?;

    segments.try_fold(root, |pkg, segment| {
        pkg.pkgs.iter().find(|p| p.name == segment)
    })
}
```

## The 'doc' sub command

```text
$ purple-garden doc
Purple garden standard library packages:
io
strings
conv
test
$ purple-garden doc io
import (io)

Package io provides rudimentary I/O primitives,
like writing and reading from file descriptors

fn println(Str) Void
fn print(Str) Void

$ purple-garden doc io.println
fn println(Str) Void
        writes its argument to stdout, with a newline appended
```

# Extending the Tokenizer

```rust
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum Type<'t> {
    // ...
    Dot,
    // ...
    Import,
    // ...
}
```

```rust
#[inline]
fn as_keyword(&self, inner: &'l str) -> Option<Token<'l>> {
    let as_type = Some(match inner {
        "import" => Type::Import,
        // ...
        _ => return None,
    })?;

    Some(self.make_tok(as_type))
}
```

```rust
pub fn one(&mut self) -> Result<Token<'l>, PgError> {
    self.skip_whitespace();

    if self.at_end() {
        return Ok(self.make_tok(Type::Eof));
    }

    let t = match self
        .cur()
        .ok_or_else(|| self.make_err("Unexpected end of file", self.col))?
    {
        // ...
        b'.' => self.make_tok(Type::Dot),
        // ...
        c if c.is_ascii_alphabetic() || c == b'_' => {
            let start = self.pos;
            self.advance();
            while self
                .cur()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                self.advance();
            }

            let inner = str::from_utf8(&self.input[start..self.pos])
                .map_err(|_| self.make_err("Invalid ut8 input", self.col))?;

            return Ok(match self.as_keyword(inner) {
                Some(as_keyword) => as_keyword,
                None => self.make_tok(Type::Ident(inner)),
            });
        }
        // ...
    };

    self.advance();

    Ok(t)
}
```

# Parsing and adding Import and Usage Nodes

```rust
pub enum Node<'node> {
    /// <target>(<args>)
    Call {
        id: usize,
        target: Box<Node<'node>>,
        args: Vec<Node<'node>>,
    },

    /// <target>.<name>
    Field {
        id: usize,
        target: Box<Node<'node>>,
        name: Token<'node>,
    },

    /// import ("<pkg name>" "<pkg name>")
    Import {
        id: usize,
        src: Token<'node>,
        /// list of packages to import as strings
        pkgs: Vec<Token<'node>>,
    },
}
```

```rust
fn parse_prefix(&mut self) -> Result<Node<'p>, PgError> {
    match self.cur().t {
        Type::Import => self.parse_import(),
        // ...
    }
}


fn parse_import(&mut self) -> Result<Node<'p>, PgError> {
    let src = self.cur.clone();
    // skip Type::Import
    self.advance()?;

    // single package import:
    // import "io"
    if let Type::S(_) = self.cur().t {
        let pkgs = vec![self.cur().clone()];
        // skip pkg name
        self.advance()?;

        return Ok(Node::Import {
            src,
            id: self.next_id(),
            pkgs,
        });
    }

    // multiple package import:
    // import ("io" "runtime")

    self.expect(Type::BraceLeft)?;

    let mut pkgs = Vec::new();

    while !self.at_end() && self.cur().t != Type::BraceRight {
        let &Token { t: Type::S(_), .. } = self.cur() else {
            return Err(PgError::with_msg(
                "Malformed import",
                "Only strings are allowed as import paths",
                &self.cur,
            ));
        };
        pkgs.push(self.cur().clone());
        self.advance()?;
    }

    self.expect(Type::BraceRight)?;
    Ok(Node::Import {
        src,
        id: self.next_id(),
        pkgs,
    })
}


fn parse_expr(&mut self, min_bp: u8) -> Result<Node<'p>, PgError> {
    let mut lhs = match self.cur().t { /* ... */ };

    // postfix parsing loop
    loop {
        match self.cur().t {
            Type::Dot => {
                self.advance()?;
                let field = self.expect_ident()?;

                lhs = Node::Field {
                    id: self.next_id(),
                    target: Box::new(lhs),
                    name: field,
                };
            }

            Type::BraceLeft => {
                self.advance();
                let mut args = vec![];

                while !self.at_end() && self.cur().t != Type::BraceRight {
                    args.push(self.parse_prefix()?);
                }

                self.expect(Type::BraceRight);
                lhs = Node::Call {
                    id: self.next_id(),
                    target: Box::new(lhs),
                    args,
                }
            }
            _ => break,
        }
    }

    // infix parsing loop
    while let Type::Plus
    | Type::Minus
    | Type::Asteriks
    | Type::Slash
    | Type::Equal
    | Type::DoubleEqual
    | Type::As
    | Type::LessThan
    | Type::GreaterThan = self.cur().t
    {
        // ...
    }

    Ok(lhs)
}
```

# Registering packages and method calls in the typechecker

```rust
#[derive(Default, Debug)]
pub struct Typechecker<'t> {
    // ...

    /// map a pkg name to a map of its methods and their types
    packages: HashMap<&'t str, HashMap<&'t str, FunctionType>>,
}
```

## Resolving packages

```rust
Node::Import { id, pkgs, src } => {
    if pkgs.is_empty() {
        return Err(PgError::with_msg(
            "Empty import statement",
            "Import without any paths to import is considered invalid",
            src,
        ));
    }

    for pkg_tok in pkgs {
        let lex::Type::S(pkg_name) = pkg_tok.t else {
            unreachable!();
        };

        let Some(pkg) = pstd::resolve_pkg(pkg_name) else {
            return Err(PgError::with_msg(
                "Unresolvable pkg import",
                format!("Wasnt able to find a package named `{pkg_name}`"),
                pkg_tok,
            ));
        };

        crate::trace!("ty: resolved pkg `{}`", pkg.name);

        self.packages.insert(
            pkg.name,
            pkg.fns
                .iter()
                .map(|f| {
                    crate::trace!("ty: registered `{}.{}`", pkg.name, f.name);
                    (
                        f.name,
                        FunctionType {
                            args: f.args.to_vec(),
                            ret: f.ret.clone(),
                        },
                    )
                })
                .collect(),
        );
    }

    Type::Void
}
```

## Typechecking package calls

```rust
Node::Call { id, target, args } => {
    let (tok, inner_name, fun) = match target.as_ref() {
        Node::Field { id, target, name } => {
            let Node::Ident {
                name:
                    lex::Token {
                        t: lex::Type::Ident(pkg_name),
                        ..
                    },
                ..
            } = target.as_ref()
            else {
                // TODO: add error handling for non ident call targets
                unreachable!();
            };

            let lex::Token {
                t: lex::Type::Ident(inner_name),
                ..
            } = name
            else {
                unreachable!();
            };

            let Some(pkg) = self.packages.get(pkg_name) else {
                return Err(PgError::with_msg(
                    "Undefined package",
                    format!("Can't find package `{}`", pkg_name),
                    name,
                ));
            };

            let Some(fun) = pkg.get(inner_name).cloned() else {
                return Err(PgError::with_msg(
                    "Undefined function",
                    format!("Call to undefined function `{}.{}`", pkg_name, inner_name),
                    name,
                ));
            };
            (name, inner_name, fun)
        }
        // ...
        _ => unreachable!(),
    };

    if args.len() != fun.args.len() {
        return Err(PgError::with_msg(
            "Function argument count mismatch",
            format!(
                "`{}` requires {} arguments, got {}",
                inner_name,
                fun.args.len(),
                args.len()
            ),
            tok,
        ));
    }

    self.map.insert(*id, fun.ret.clone());

    for (i, provided_node) in args.iter().enumerate() {
        let provided_type = self.node(provided_node)?;
        let expected_type = &fun.args[i];

        if expected_type != &provided_type {
            return Err(PgError::with_msg(
                "Function argument type mismatch",
                format!(
                    "`{}` arg{} expected type {}, got {} instead",
                    inner_name, i, expected_type, provided_type,
                ),
                tok,
            ));
        }
    }

    fun.ret
}
```

# A new IR Instruction Variant for std Method Calls

```rust
pub enum Instr<'i> {
    // ...
    Sys {
        dst: TypeId,
        path: &'i str,
        func: &'i pstd::Fn,
        args: Vec<Id>,
    },
    // ...
}
```

## Lowering Node::Import

```rust
#[derive(Default)]
pub struct Lower<'lower> {
    // ...
    packages: HashMap<&'lower str, (&'lower pstd::Pkg, HashMap<&'lower str, &'lower pstd::Fn>)>,
}
```

```rust
Node::Import { src, pkgs, .. } => {
    for pkg_tok in pkgs {
        let Token {
            t: Type::S(as_str), ..
        } = pkg_tok
        else {
            unreachable!();
        };

        // the type checker already checks all packages are valid
        let Some(pkg) = pstd::resolve_pkg(as_str) else {
            unreachable!()
        };

        self.packages
            .insert(as_str, (pkg, pkg.fns.iter().map(|f| (f.name, f)).collect()));
    }
    None
}
```

## Lowering the call

```rust
Node::Call { target, args, .. } => {
    let mut a = vec![];
    for arg in args {
        let Some(id) = self.lower_node(arg)? else {
            unreachable!();
        };
        a.push(id);
    }

    let dst_id = self.ctx.id_store.new_value();
    let mut dst = TypeId {
        // this is a placeholder
        ty: ptype::Type::Void,
        id: dst_id,
    };

    match target.as_ref() {
        // 'syscall' / stdlib call
        Node::Field { target, name, .. } => {
            let Node::Ident {
                name:
                    lex::Token {
                        t: lex::Type::Ident(pkg_name),
                        ..
                    },
                ..
            } = target.as_ref()
            else {
                unreachable!();
            };

            let lex::Token {
                t: lex::Type::Ident(inner_name),
                ..
            } = name
            else {
                unreachable!();
            };

            // both unwrappable because the typechecker makes sure everything is fine
            let fun = self
                .packages
                .get(pkg_name)
                .unwrap()
                .1
                .get(inner_name)
                .unwrap();

            dst.ty = fun.ret.clone();
            self.emit(Instr::Sys {
                dst,
                path: pkg_name,
                func: fun,
                args: a,
            });
        }
        // ...
    };

    Some(dst_id)
}
```

# 'Op::Sys' and Lowering to Bytecode

```rust
pub enum Op {
    Sys { idx: u16 },
}
```

```rust
ir::Instr::Sys {
    dst,
    path,
    func,
    args,
} => {
    let idx = self.std_fns.intern(func.ptr);
    for (i, &ir::Id(arg)) in args.iter().enumerate() {
        let (dst, src) = (i as u8, arg as u8);
        if dst != src {
            self.emit(Op::Mov { dst, src });
        }
    }

    let TypeId {
        id: ir::Id(dst), ..
    } = dst;
    self.emit(Op::Sys { idx: idx as u16 });
    self.emit(Op::Mov {
        dst: *dst as u8,
        src: 0,
    });
}
```

# Std interactions in the virtual machine

```rust
pub struct Vm<'vm> {
    // ...
    pub syscalls: Vec<BuiltinFn>,
}
```

```rust
pub fn run(&mut self) -> Result<(), Anomaly> {
    let regs = self.r.as_mut_ptr();
    let instructions = self.bytecode.as_mut_ptr();
    let instructions_len = self.bytecode.len();
    let globals = self.globals.as_mut_ptr();
    let syscalls = self.syscalls.as_mut_ptr();

    macro_rules! r {
        ($n:tt) => {
            (&*regs.add($n as usize))
        };
    }

    macro_rules! r_mut {
        ($n:tt) => {
            *regs.add($n as usize)
        };
    }

    let mut pc = self.pc;

    while pc < instructions_len {
        let op = unsafe { *instructions.add(pc) };
        match op {
            Op::Sys { idx } => unsafe {
                r_mut!(0) = (*syscalls.add(idx as usize))(self);
            },
            // ...
        }

        pc += 1;
    }

    self.pc = pc;

    Ok(())
}
```

# Introspection in the bytecode disassembly

```asm
00000000 <entry>:
  0000:    load_global r0, 0    ; = "hello world"
  0001:    sys 0 <io.println>   ; @ 0x564339abea60
  0002:    mov r1, r0
```

```rust
pub fn disassemble(&self) {
    let funcs_by_pc: HashMap<u32, &bc::BcFunc> = self
        .cc
        .functions
        .values()
        .map(|f| (f.pc as u32, f))
        .collect();

    let globals = self.cc.globals.clone().into_vec();
    let strings = self.cc.strings.clone().into_vec();
    let std_fns = self.cc.std_fns.clone().into_vec();
    let std_mapping = Self::build_fn_map();

    let mut cur_func = self.cc.functions.get(&Id(0)).unwrap();
    for (pc, instr) in self.bc.iter().enumerate() {
        if let Some(func) = funcs_by_pc.get(&(pc as u32)) {
            cur_func = func;
            println!("\n{:08x} <{}>:", pc, func.name);
        }

        println!(
            "  {:04x}:    {}",
            pc,
            match instr {
                // ...
                Op::Sys { idx } => format!(
                    "sys {idx} <{}> \t; @ 0x{:x}",
                    std_mapping.get(&std_fns[*idx as usize]).unwrap(),
                    std_fns[*idx as usize] as usize,
                ),
            }
        );
    }
}
```
