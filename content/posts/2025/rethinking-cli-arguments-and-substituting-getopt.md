---
title: "Rethinking How I Deal With CLI Arguments (replacing getopt)"
summary: "Shortcomings of getopt, parsing CLI arguments into flags, no POSIX and a lot of implementation details"
date: 2025-05-10
tags:
  - c
---

This article covers the issues I found myself having while using `getopt.h` for
a programming language bytecode interpreter pipeline I am currently working on
([`purple-garden`](https://github.com/xNaCly/purple-garden)[^pg]),
implementation details for the replacement I wrote, examples of how to use the
new solution and how I replaced the previous implementation with the new one
using `6cl`[^6cl].

[^pg]: purple-garden is a WIP of a lisp like high performance scripting language

{{<callout type="Tip or: TL;DR">}}

#### `getopt.h` kinda sucks to use, because:

- You have to write the help page and the usage page yourself
- You have to keep track of all flags and their handling at least twice (once
  in your flag definitions, once for short option names and once in their
  handling)
- Flags aren't typed, so all option arguments are just C strings accessible via
  global state `optarg`
- Default values aren't really a thing
- Option prefix is hardcoded to `-` for short options and `--` for long options
  (thanks for that [UNIX and POSIX](https://www.man7.org/linux/man-pages/man3/getopt.3.html))

#### I solved these issues by:

- Generating help and usage pages from the list of options
- Single flag list, no short and long definition in multiple places
- Typing flag options with seven types, range validation (`float.h`,
  `limits.h`) and default values:
  - string
  - boolean
  - character
  - integer and long
  - float and double
- Defaults and types are just fields of the flag struct in the flag definition
- Macro for setting the prefix and single prefix for all options

{{</callout>}}

I wrote [`6cl`](https://github.com/xNaCly/6cl) to fill the gaps I encountered.
6cl is an opiniated command line option parsing library for 6wm[^6wm] and
purple garden

[^6cl]:
    named after the 6 looking like the G of garden. Combined with cl, which
    is short for command line

[^6wm]:
    a planned fork of dwm to replace the `config.h` driven configuration
    with a purple garden script

{{<callout type="Warning">}}
As always, I am not perfect and neither are my code and blog articles, thus if
you find any issues or have any questions, feel free to email me:
[contact@xnacly.me](mailto:contact@xnacly.me) or `contact (at) xnacly.me`.
{{</callout>}}

## Current state

The purple-garden (pg), interpreter accepts a number of options:

```text
$ ./purple_garden -h
usage: purple_garden [-v | --version] [-h | --help]
                     [-d | --disassemble] [-b<size> | --block-allocator=<size>]
                     [-a | --aot-functions] [-m | --memory-usage]
                     [-V | --verbose] [-r<input> | --run=<input>] <file.garden>

Options:
        -v, --version
                display version information

        -h, --help
                extended usage information

        -d, --disassemble
                readable bytecode representation with labels,
                globals and comments

        -b=<size>, --block-allocator=<size>
                use block allocator instead of garbage collection

        -a, --aot-functions
                compile all functions to machine code

        -m, --memory-usage
                display the memory usage of parsing,
                compilation and the virtual machine

        -V, --verbose
                verbose logging

        -r=<input>, --run=<input>
                executes the argument as if an input file was given
```

### Command line argument parsing using getopt

I handle these by first defining a struct to hold all options, for later reference:

```c
typedef struct {
  // options - int because getopt has no bool support

  // use block allocator instead of garbage collection
  size_t block_allocator;
  // compile all functions to machine code
  int aot_functions;
  // readable bytecode representation with labels, globals and comments
  int disassemble;
  // display the memory usage of parsing, compilation and the virtual machine
  int memory_usage;

  // executes the argument as if an input file was given
  char *run;

  // verbose logging
  int verbose;

  // options in which we exit after toggle
  int version;
  int help;

  // entry point - last argument thats not an option
  char *filename;
} Args;
```

After that I define the list of options so I can keep track of them once getopt
does its stuff:

```c
typedef struct {
  const char *name_long;
  const char name_short;
  const char *description;
  const char *arg_name;
} cli_option;

// WARN: DO NOT REORDER THIS - will result in option handling issues
static const cli_option options[] = {
    {"version", 'v', "display version information", ""},
    {"help", 'h', "extended usage information", ""},
    {"disassemble", 'd', "readable bytecode representation with labels, globals and comments", ""},
    {"block-allocator", 'b', "use block allocator instead of garbage collection", "<size>"},
    {"aot-functions", 'a', "compile all functions to machine code", ""},
    {"memory-usage", 'm', "display the memory usage of parsing, compilation and the virtual machine", ""},
    {"verbose", 'V', "verbose logging", ""},
    {"run", 'r', "executes the argument as if an input file was given", "<input>"},
};
```

The heavy lifting is of course done in the `Args_parse` function:

```c
Args Args_parse(int argc, char **argv) {
    // [...] 1.-6.
}
```

1. Convert the array of `cli_option`'s to `getopt`'s `option`

   ```c
       Args a = (Args){0};
       // MUST be in sync with options, otherwise this will not work as intended
       struct option long_options[] = {
         {options[0].name_long, no_argument, &a.version, 1},
         {options[1].name_long, no_argument, &a.help, 1},
         {options[2].name_long, no_argument, &a.disassemble, 1},
         {options[3].name_long, required_argument, 0, 'b'},
         {options[4].name_long, no_argument, &a.aot_functions, 1},
         {options[5].name_long, no_argument, &a.memory_usage, 1},
         {options[6].name_long, no_argument, &a.verbose, 1},
         {options[7].name_long, required_argument, 0, 'r'},
         {0, 0, 0, 0},
       };
   ```

2. Pass the array to `getopt_long` with the matching short flag definition `vhdb:amVr:` (third location to define flags)

   ```c
       int opt;
       while ((opt = getopt_long(argc, argv, "vhdb:amVr:", long_options, NULL)) !=
            -1) {
           //  [...]
       }
   ```

3. Handle short options separately from long option "automatic" handling (touching every flag twice)

   ```c
           switch (opt) {
           case 'v':
             a.version = 1;
             break;
           case 'V':
             a.verbose = 1;
             break;
           case 'h':
             a.help = 1;
             break;
           case 'd':
             a.disassemble = 1;
             break;
           case 'r':
             a.run = optarg;
             break;
           case 'b':
             char *endptr;
             size_t block_size = strtol(optarg, &endptr, 10);
             ASSERT(endptr != optarg, "args: Failed to parse number from: %s", optarg);
             a.block_allocator = block_size;
             break;
           case 'a':
             a.aot_functions = 1;
             break;
           case 'm':
             a.memory_usage = 1;
             break;
           case 0:
             break;
           default:
             usage();
             exit(EXIT_FAILURE);
           }
   ```

4. Store all non flags as rest, representing the entry file (`filename`)

   ```c
       if (optind < argc) {
           a.filename = argv[optind];
       }
   ```

5. Act on commands, like `--version`, `--help` and their short variants

   ```c
       if (a.version) {
           // [...]
       } else if (a.help) {
           usage();
           // [...]
       }
   ```

6. Error if no input to the interpreter is detected

   ```c
     if (a.filename == NULL && a.run == NULL) {
       usage();
       fprintf(stderr, "error: Missing a file? try `-h/--help`\n");
       exit(EXIT_FAILURE);
     };
   ```

## 6cl Design, API and Examplary Usage

The API design is inspired by Go's [flag](https://pkg.go.dev/flag) package,
Google's [gflag](https://gflags.github.io/gflags/), my general experience with
programming languages (Go, Rust, C, etc.) and my attempt to create an ergonomic
interface around the constraints of the C programming language.

By ergnomic I mean:

- single location for defining flags (no setting and handling them multiple times)
- option format
  - boolean options have no argument
  - merged short and long options (no `-s`, `--save`, but `-s` and `-save`)
  - no combined options (no `-xvf` or `-lah`, but `-x -v -f` and `-l -a -h`)
  - no name and option merges, such as `+DCONSTANT=12` or `+n128`, but rather
    `+D CONSTANT=12` and `+n 128`
- type safe and early errors if types can't be to parsed or over-/underflows occur
- type safe default values if flags aren't specified

### Defining Flags

A flag consists of a long name, a short name, a type, a description and a
default value that matches its type.

The type is defined as an enum:

```c
typedef enum {
  SIX_STR,
  SIX_BOOL,
  SIX_CHAR,
  SIX_INT,
  SIX_LONG,
  SIX_FLOAT,
  SIX_DOUBLE,
} SixFlagType;
```

The flag itself holds all aforementioned fields:

```c
typedef struct {
  // name of the flag, for instance +<name>; +help
  const char *name;
  // short name, like +<short_name>; +h
  char short_name;
  // Defines the datatype
  SixFlagType type;
  // used in the help page
  const char *description;

  // typed result values, will be filled with the value if any is found found
  // for the option, or with the default value thats already set.
  union {
    // string value
    char *s;
    // boolean value
    bool b;
    // char value
    char c;
    // int value
    int i;
    // long value
    long l;
    // float value
    float f;
    // double value
    double d;
  };
} SixFlag;
```

So a flag `+pi <double> / +p <double>` would be defined as:

```c
SixFlag pi = {
    .name = "pi",
    .short_name = 'p',
    .d = 3.1415,
    .type = SIX_DOUBLE,
    .description = "define pi",
};
```

This has to be passed to the `Six` struct, holding the available flags:

```c
typedef struct Six {
  SixFlag *flags;
  size_t flag_count;
  // usage will be postfixed with this
  const char *name_for_rest_arguments;
  // rest holds all arguments not matching any defined options
  char *rest[SIX_MAX_REST];
  size_t rest_count;
} Six;
```

The fields `flags` and `flag_count` must be set before calling `SixParse`:

```c
typedef enum { UNKNOWN = -1, PI} Option;

SixFlag options[] = {
    [PI] = {
        .name = "pi",
        .short_name = 'p',
        .d = 3.1415,
        .type = SIX_DOUBLE,
        .description = "define pi",
    },
};
Six s = {0};
s.flags = options;
s.flag_count = sizeof(options) / sizeof(SixFlag);
SixParse(&s, argc, argv);
```

### Accessing Flags

The flags can be accessed by indexing into the options array:

```c
double pi = s.flags[PI].d;
printf("%f\n", pi);
```

### Fusing into an Example

I use an example to test the pipeline, so I'll just dump this one here:

```c
/*
 * A dice roller that simulates rolling N dice with M sides, optionally
 * labeled, and with verbose output to print each roll result.
 *
 * $ gcc ./dice.c ../6cl.c -o dice
 * $ ./dice +n 4 +m 6
 * => 14
 * $ ./dice +rolls 2 +sides 20 +label "STR"
 * STR: => 29
 * $ ./dice +n 3 +m 10 +v
 * Rolled: 3 + 7 + 5 =15
 */
#include "../6cl.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ERR(FMT, ...) fprintf(stderr, "dice: " FMT "\n", ##__VA_ARGS__);

void dice(int *throws, unsigned int n, unsigned int m) {
  for (size_t i = 0; i < n; i++) {
    throws[i] = (rand() % m) + 1;
  }
}

typedef enum { UNKNOWN = -1, ROLLS, SIDES, LABEL, VERBOSE } Option;

int main(int argc, char **argv) {
  srand((unsigned int)time(NULL));

  SixFlag options[] = {
      [ROLLS] = {.name = "rolls",
                 .short_name = 'n',
                 .i = 2,
                 .type = SIX_INT,
                 .description = "times to roll"},
      [SIDES] = {.name = "sides",
                 .short_name = 'm',
                 .i = 6,
                 .type = SIX_INT,
                 .description = "sides the dice has"},
      [LABEL] =
          {
              .name = "label",
              .short_name = 'l',
              .s = "=> ",
              .type = SIX_STR,
              .description = "prefix for the dice roll result",
          },
      [VERBOSE] =
          {
              .name = "verbose",
              .short_name = 'v',
              .type = SIX_BOOL,
              .description = "print all rolls, not only the result",
          },
  };
  Six s = {0};
  s.flags = options;
  s.flag_count = sizeof(options) / sizeof(SixFlag);

  SixParse(&s, argc, argv);
  if (s.flags[VERBOSE].b) {
    printf("Config{rolls=%d, sides=%d, label=`%s`}\n", s.flags[ROLLS].i,
           s.flags[SIDES].i, s.flags[LABEL].s);
  }

  if (options[ROLLS].i < 1) {
    ERR("Rolls can't be < 1");
    return EXIT_FAILURE;
  }

  int throws[options[ROLLS].i];
  dice(throws, options[ROLLS].i, options[SIDES].i);

  int cum = 0;
  for (int i = 0; i < options[ROLLS].i; i++) {
    int roll = throws[i];
    cum += roll;
    if (options[VERBOSE].b) {
      printf("[roll=%02d]::[%02d/%02d]\n", i + 1, roll, options[SIDES].i);
    }
  }

  printf("%s%d\n", options[LABEL].s, cum);

  return EXIT_SUCCESS;
}
```

## Generating Documentation

From here on out, I'll show how I implemented the command line parser and the
API surface.

If the user passes a malformed input to a well written application, it should
provide a good error message, a usage overview and a note on how to get in
depth help. Since each option has a short name, a long name, a type, a default
value and a description - I want to display all of the aforementioned in the
help and a subset in the usage page.

### Usage

The usage page is displayed if the application is invoked with either `+h` or
`+help` or the 6cl parser hits an error (for the former two just as a prefix to
the help page):

```text
$ ./examples/dice.out +k
Unknown short option 'k'
usage ./examples/dice.out: [ +n / +rolls <int=2>] [ +m / +sides <int=6>]
                           [ +l / +label <string=`=> `>] [ +v / +verbose]
                           [ +h / +help]
```

I created a helper for printing a flag and all its options - `print_flag`:

```c
void print_flag(SixFlag *f, bool long_option) {
  char *pre_and_postfix = "[]";
  if (long_option) {
    putc('\t', stdout);
    pre_and_postfix = "  ";
  }

  printf("%c %c%c / %c%s", pre_and_postfix[0], SIX_OPTION_PREFIX, f->short_name,
         SIX_OPTION_PREFIX, f->name);
  if (f->type != SIX_BOOL) {
    printf(" <%s=", SIX_FLAG_TYPE_TO_MAP[f->type]);
    switch (f->type) {
    case SIX_STR:
      printf("`%s`", f->s);
      break;
    case SIX_CHAR:
      putc(f->c, stdout);
      break;
    case SIX_INT:
      printf("%d", f->i);
      break;
    case SIX_LONG:
      printf("%ld", f->l);
      break;
    case SIX_FLOAT:
      printf("%g", f->f);
      break;
    case SIX_DOUBLE:
      printf("%g", f->d);
      break;
    default:
    }
    putc('>', stdout);
  }
  putc(pre_and_postfix[1], stdout);
  putc(' ', stdout);

  if (long_option) {
    if (f->description) {
      printf("\n\t\t%s\n", f->description);
    }
    putc('\n', stdout);
  }
}
```

After every two options there is a newline inserted to make the output more readable.

```c
static SixFlag HELP_FLAG = {
    .name = "help",
    .short_name = 'h',
    .description = "help page and usage",
    .type = SIX_BOOL,
};

// part of -h, --help, +h, +help and any unknown option
static void usage(const char *pname, const Six *h) {
  // should i put this to stdout or stderr
  printf("usage %s: ", pname);
  size_t len = strlen(pname) + 7;
  for (size_t i = 0; i < h->flag_count; i++) {
    print_flag(&h->flags[i], false);
    if ((i + 1) % 2 == 0 && i + 1 < h->flag_count) {
      printf("\n%*.s ", (int)len, "");
    }
  }

  printf("\n%*.s ", (int)len, "");
  print_flag(&HELP_FLAG, false);

  if (h->name_for_rest_arguments) {
    puts(h->name_for_rest_arguments);
  } else {
    puts("");
  }
}
```

### Examples

To generate two examples (one with long names and one with short names), the default values are used:

```text
Examples:
        ./examples/dice.out +n 2 +m 6 \
                            +l "=> " +v

        ./examples/dice.out +rolls 2 +sides 6 \
                            +label "=> " +verbose
```

As with the usage, after every two options there is a newline inserted.

```c
static void help(const char *pname, const Six *h) {
  size_t len = strlen(pname);
  // [...]

  printf("Examples: ");
  for (size_t i = 0; i < 2; i++) {
    printf("\n\t%s ", pname);
    for (size_t j = 0; j < h->flag_count; j++) {
      SixFlag *s = &h->flags[j];
      if (i) {
        printf("%c%s", SIX_OPTION_PREFIX, s->name);
      } else {
        printf("%c%c", SIX_OPTION_PREFIX, s->short_name);
      }
      switch (s->type) {
      case SIX_STR:
        printf(" \"%s\"", s->s);
        break;
      case SIX_CHAR:
        printf(" %c", s->c);
        break;
      case SIX_INT:
        printf(" %d", s->i);
        break;
      case SIX_LONG:
        printf(" %zu", s->l);
        break;
      case SIX_FLOAT:
      case SIX_DOUBLE:
        printf(" %g", s->f);
        break;
      case SIX_BOOL:
      default:
        break;
      }
      putc(' ', stdout);
      if ((j + 1) % 2 == 0 && j + 1 < h->flag_count) {
        printf("\\\n\t %*.s", (int)len, "");
      }
    }
    puts("");
  }
}
```

### Help Page

The help page merges the usage, the extended option display (with description)
and the example sections:

```text
$ ./examples/dice.out +help
usage ./examples/dice.out: [ +n / +rolls <int=2>] [ +m / +sides <int=6>]
                           [ +l / +label <string=`=> `>] [ +v / +verbose]
                           [ +h / +help]

Option:
          +n / +rolls <int=2>
                times to roll

          +m / +sides <int=6>
                sides the dice has

          +l / +label <string=`=> `>
                prefix for the dice roll result

          +v / +verbose
                print all rolls, not only the result

          +h / +help
                help page and usage

Examples:
        ./examples/dice.out +n 2 +m 6 \
                            +l "=> " +v

        ./examples/dice.out +rolls 2 +sides 6 \
                            +label "=> " +verbose
```

With usage, options and examples:

```c
static void help(const char *pname, const Six *h) {
  usage(pname, h);
  size_t len = strlen(pname);
  printf("\nOption:\n");
  for (size_t j = 0; j < h->flag_count; j++) {
    print_flag(&h->flags[j], true);
  }
  print_flag(&HELP_FLAG, true);

  printf("Examples: ");
  for (size_t i = 0; i < 2; i++) {
    printf("\n\t%s ", pname);
    for (size_t j = 0; j < h->flag_count; j++) {
      SixFlag *s = &h->flags[j];
      if (i) {
        printf("%c%s", SIX_OPTION_PREFIX, s->name);
      } else {
        printf("%c%c", SIX_OPTION_PREFIX, s->short_name);
      }
      switch (s->type) {
      case SIX_STR:
        printf(" \"%s\"", s->s);
        break;
      case SIX_CHAR:
        printf(" %c", s->c);
        break;
      case SIX_INT:
        printf(" %d", s->i);
        break;
      case SIX_LONG:
        printf(" %zu", s->l);
        break;
      case SIX_FLOAT:
      case SIX_DOUBLE:
        printf(" %g", s->f);
        break;
      case SIX_BOOL:
      default:
        break;
      }
      putc(' ', stdout);
      if ((j + 1) % 2 == 0 && j + 1 < h->flag_count) {
        printf("\\\n\t %*.s", (int)len, "");
      }
    }
    puts("");
  }
}
```

## Detecting Short Flags

Since there are less than 256 ascii values that are valid for a short option,
specifically the character omitting the prefix, I use a table lookup for
checking both if there is a flag registered for that character and at what
location the option is in `Six.flags`.

```c
short table_short[256] = {0};

// registering all options
for (size_t i = 0; i < six->flag_count; i++) {
    SixFlag *f = &six->flags[i];

    // [...]
    if (f->short_name) {
      table_short[(int)f->short_name] = i + 1;
    }
}
```

Zeroing the array serves the purpose of treating all characters that don't have
an associated option to resolve to 0, making for a pretty good error handling.
However, this requires incrementing all indices by one to differentiate from
the zero value (I could've abstracted this via a custom `Option` struct or
something, but I couldn't be bothered).

> For our `+p` example we have the index 1(0) into the option array at the table
> index `112`, since we increment the index by one, as explained above.

Detecting short options is a thing of indexing a character into an array, so we
do exactly that while processing the arguments:

```c
for (size_t i = 1; i < argc; i++) {
    SixStr arg_cur = (SixStr){.p = (argv[i]), .len = strnlen(argv[i], 256)};

    // not starting with PREFIX means: no option, thus rest
    if (arg_cur.p[0] != SIX_OPTION_PREFIX) {
      if (six->rest_count + 1 >= SIX_MAX_REST) {
        fprintf(stderr, "Not enough space left for more rest arguments\n");
        goto err;
      }
      six->rest[six->rest_count++] = argv[i];
      continue;
    }

    // check if short option
    if (arg_cur.len == 2) {
      int cc = arg_cur.p[1];
      if (cc > 256 || cc < 0) {
        fprintf(stderr, "Unknown short option '%c'\n", arg_cur.p[1]);
        goto err;
      }

      // single char option usage/help page
      if (cc == 'h') {
        help(argv[0], six);
        exit(EXIT_SUCCESS);
      }

      // check if short option is a registered one
      short option_idx = table_short[(short)arg_cur.p[1]];
      if (!option_idx) {
        fprintf(stderr, "Unknown short option '%c'\n", arg_cur.p[1]);
        goto err;
      }

      // we decrement option_idx, since we zero the lookup table, thus an
      // empty value is 0 and the index of the first option is 1, we correct
      // this here
      option_idx--;

      int offset = process_argument(&six->flags[option_idx], i, argc, argv);
      if (offset == -1) {
        goto err;
      }
      i += offset;
    } else {
        // [...]
    }
}
```

The tricky parts have comments, the rest should be obvious:

1. check if the current argv member is a short option
   - if `h`: print the help page, end
2. check if option is in the registered table
3. process the argument for said option
4. modify index with offset returned from parsing arguments (because an option
   argument can span multiple process arguments)

## Detecting Long Flags

Long flags is a whole other story since we can't match on a single character,
we cant hardcode a switch or an if since that would defeat the dynamic nature
of 6cl - the solution:

> **Hashing**

If we hash all flags at register time, use that hash to index into a table,
store a pointer to the corresponding option at said hash/index, hash the flags
we encounter while parsing the command arguments and use this hash to index
into the table - we have implemented a lookup table that allows us to keep
things dynamic without the consumer having to do any work with `strncmp` or
macro code gen.

### Hash Algorithm

Good old
[fnv1a](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#FNV-1a_hash).
I used it in [HashMap in 25 lines of C](/posts/2024/c-hash-map/) and I use it
in purple garden for interning strings and identifiers - its fast, has a good
distribution and is easy to implement:

```c
static size_t fnv1a(const char *str, size_t len) {
#define FNV_OFFSET_BASIS 0x811c9dc5
#define FNV_PRIME 0x01000193

  size_t hash = FNV_OFFSET_BASIS;
  for (size_t i = 0; i < len; i++) {
    hash ^= str[i];
    hash *= FNV_PRIME;
  }

  return hash;
}
```

### Registering Options

As with the short options, we must first register the long options by their
name, or rather, by their hash:

```c
// maps a strings hash to its index into the option array
short hash_table_long[__HASH_TABLE_SIZE] = {0};

for (size_t i = 0; i < six->flag_count; i++) {
    SixFlag *f = &six->flags[i];

    // we increment the index by one here, since we use all tables and arrays
    // zero indexed, distinguishing between a not found and the option at index
    // 0 is therefore clear
    hash_table_long[fnv1a(f->name, strnlen(f->name, 256)) & __HASH_TABLE_MASK] = i + 1;

    // [...]
}
```

The `& __HASH_TABLE_MASK` makes sure we truncate our hashes to the table size:

```c
#define __HASH_TABLE_SIZE 512
#define __HASH_TABLE_MASK (__HASH_TABLE_SIZE - 1)
```

We use this to now compute the hash for each long option we encounter and check
if the table contains an option index:

### Detecting Options by Their Names

As introduced before, we enter this path if the current argument isn't two
characters: `<PREFIX><char>`, but longer:

1. Modify the string window to skip the char prefix:
   - from: `+string` (start=0,length=7)
   - to: `string` (start=1,length=6)
2. Check if the window matches `help`, print help and exit if so
3. Compute the hash for the window
4. Check if hash is in registered option table
5. Process arguments

```c
for (size_t i = 1; i < argc; i++) {
    SixStr arg_cur = (SixStr){.p = (argv[i]), .len = strnlen(argv[i], 256)};

    // check if short option
    if (arg_cur.len == 2) {
        // [..]
    } else {
        // strip first char by moving the start of the window one to the right
        arg_cur.p++;
        arg_cur.len--;

        // long help page with option description and stuff
        if (strncmp(arg_cur.p, help_str.p, help_str.len) == 0) {
            help(argv[0], six);
            exit(EXIT_SUCCESS);
        }

        size_t idx = hash_table_long[fnv1a(arg_cur.p, arg_cur.len) & __HASH_TABLE_MASK];
        if (!idx) {
            fprintf(stderr, "Unknown option '%*s'\n", (int)arg_cur.len, arg_cur.p);
            goto err;
        }

        // decrement idx since we use 0 as the no option value
        idx--;

        SixFlag *f = &six->flags[idx];
        int offset = process_argument(f, i, argc, argv);
        if (offset == -1) {
            goto err;
        }
        i += offset;
    }
}
```

## Handling Option Arguments

Handling arguments is fairly easy, its just a big switch, a lot of parsing
values from strings to other things and validating the results of said
parsing:

```c
static int process_argument(SixFlag *f, size_t cur, size_t argc, char **argv) {
  size_t offset = 1;
  switch (f->type) {
  case SIX_STR: {
    if (cur + 1 >= argc) {
      fprintf(stderr, "No STRING value for option '%s'\n", f->name);
      return -1;
    }
    f->s = argv[cur + 1];
    break;
  }
  case SIX_BOOL:
    f->b = true;
    offset = 0;
    break;
  case SIX_CHAR:
    if (cur + 1 >= argc) {
      fprintf(stderr, "No char value found for option '%s/%c'\n", f->name,
              f->short_name);
      return -1;
    } else if (argv[cur + 1][0] == '\0') {
      fprintf(stderr, "No char found for option '%s/%c', empty argument\n",
              f->name, f->short_name);
      return -1;
    } else if (argv[cur + 1][1] != '\0') {
      fprintf(stderr,
              "'%s/%c' value has too many characters, want one for type CHAR\n",
              f->name, f->short_name);
      return -1;
    }
    f->c = argv[cur + 1][0];
    break;
  case SIX_INT: {
    if (cur + 1 >= argc) {
      fprintf(stderr, "No INT value for option '%s/%c'\n", f->name,
              f->short_name);
      return -1;
    }
    char *tmp = argv[cur + 1];
    char *endptr = NULL;
    int errno = 0;
    long val = strtol(tmp, &endptr, 10);

    if (endptr == tmp || *endptr != '\0') {
      fprintf(stderr, "Invalid integer for option '%s/%c': '%s'\n", f->name,
              f->short_name, tmp);
      return -1;
    }

    if (val < INT_MIN || val > INT_MAX) {
      fprintf(stderr, "Integer out of range for option '%s/%c': %ld\n", f->name,
              f->short_name, val);
      return -1;
    }

    f->i = (int)val;
    break;
  }
  case SIX_LONG: {
    if (cur + 1 >= argc) {
      fprintf(stderr, "No LONG value for option '%s/%c'\n", f->name,
              f->short_name);
      return -1;
    }
    char *tmp = argv[cur + 1];
    char *endptr = NULL;
    int errno = 0;
    long val = strtol(tmp, &endptr, 10);

    if (endptr == tmp || *endptr != '\0') {
      fprintf(stderr, "Invalid LONG integer for option '%s/%c': '%s'\n",
              f->name, f->short_name, tmp);
      return -1;
    }

    if (val < LONG_MIN || val > LONG_MAX) {
      fprintf(stderr, "LONG integer out of range for option '%s/%c': %ld\n",
              f->name, f->short_name, val);
      return -1;
    }

    f->l = val;
    break;
  }
  case SIX_FLOAT: {
    if (cur + 1 >= argc) {
      fprintf(stderr, "No FLOAT value for option '%s/%c'\n", f->name,
              f->short_name);
      return -1;
    }
    char *tmp = argv[cur + 1];
    char *endptr = NULL;
    int errno = 0;
    float val = strtof(tmp, &endptr);

    if (endptr == tmp || *endptr != '\0') {
      fprintf(stderr, "Invalid FLOAT for option '%s/%c': '%s'\n", f->name,
              f->short_name, tmp);
      return -1;
    }

    if (val < FLT_MIN || val > FLT_MAX) {
      fprintf(stderr, "FLOAT out of range for option '%s/%c': %ld\n", f->name,
              f->short_name, val);
      return -1;
    }

    f->f = val;
    break;
  }
  case SIX_DOUBLE: {
    if (cur + 1 >= argc) {
      fprintf(stderr, "No DOUBLE value for option '%s/%c'\n", f->name,
              f->short_name);
      return -1;
    }
    char *tmp = argv[cur + 1];
    char *endptr = NULL;
    int errno = 0;
    double val = strtod(tmp, &endptr);

    if (endptr == tmp || *endptr != '\0') {
      fprintf(stderr, "Invalid DOUBLE for option '%s/%c': '%s'\n", f->name,
              f->short_name, tmp);
      return -1;
    }

    if (val < FLT_MIN || val > FLT_MAX) {
      fprintf(stderr, "DOUBLE out of range for option '%s/%c': %ld\n", f->name,
              f->short_name, val);
      return -1;
    }

    f->d = val;
    break;
  }
  default:
    fprintf(stderr, "Unknown type for option '%s/%c'\n", f->name,
            f->short_name);
    return -1;
  }

  return offset;
}
```

By default the returned offset is one, since we handle one argument per
option. The exception being `SixFlag::type=SIX_BOOL`, because I decided i
don't allow arguments for boolean options.

## Porting Purple Garden from Getopt to 6cl

Since I wrote this library to solve my issues with `getopt`, I introduced it
with and for that purpose and I used the interpreter as an example - I ought to
show you how I used 6cl to fix these issues:

```diff
diff --git a/Makefile b/Makefile
index 5b75a9c..3c333fc 100644
--- a/Makefile
+++ b/Makefile
@@ -44,14 +44,14 @@ run:
 
 verbose:
 	$(CC) -g3 $(FLAGS) $(RELEASE_FLAGS) $(FILES) ./main.c -o purple_garden_verbose
-	./purple_garden_verbose -V $(PG)
+	./purple_garden_verbose +V $(PG)
 
 release:
 	$(CC) -g3 $(FLAGS) $(RELEASE_FLAGS) -DCOMMIT='"$(COMMIT)"' -DCOMMIT_MSG='"$(COMMIT_MSG)"' $(FILES) ./main.c -o purple_garden
 
 bench:
 	$(CC) $(FLAGS) $(RELEASE_FLAGS) -DCOMMIT='"BENCH"' $(FILES) ./main.c -o bench
-	./bench -V $(PG)
+	./bench +V $(PG)
 
 test:
 	$(CC) $(FLAGS) -g3 -fsanitize=address,undefined -DDEBUG=0 $(TEST_FILES) $(FILES) -o ./tests/test
diff --git a/main.c b/main.c
index b372404..dedb6c2 100644
--- a/main.c
+++ b/main.c
@@ -1,9 +1,10 @@
-#include <getopt.h>
+// TODO: split this up into a DEBUG and a performance entry point
 #include <stdio.h>
 #include <stdlib.h>
 #include <sys/mman.h>
 #include <sys/time.h>
 
+#include "6cl/6cl.h"
 #include "cc.h"
 #include "common.h"
 #include "io.h"
@@ -36,158 +37,99 @@
   } while (0)
 
 typedef struct {
-  // options - int because getopt has no bool support
-
-  // use block allocator instead of garbage collection
   size_t block_allocator;
-  // compile all functions to machine code
-  int aot_functions;
-  // readable bytecode representation with labels, globals and comments
-  int disassemble;
-  // display the memory usage of parsing, compilation and the virtual machine
-  int memory_usage;
-
-  // executes the argument as if an input file was given
+  bool aot_functions;
+  bool disassemble;
+  bool memory_usage;
   char *run;
-
-  // verbose logging
-  int verbose;
-
-  // options in which we exit after toggle
+  bool verbose;
   int version;
-  int help;
-
-  // entry point - last argument thats not an option
   char *filename;
 } Args;
 
-typedef struct {
-  const char *name_long;
-  const char name_short;
-  const char *description;
-  const char *arg_name;
-} cli_option;
-
-// WARN: DO NOT REORDER THIS - will result in option handling issues
-static const cli_option options[] = {
-    {"version", 'v', "display version information", ""},
-    {"help", 'h', "extended usage information", ""},
-    {"disassemble", 'd',
-     "readable bytecode representation with labels, globals and comments", ""},
-    {"block-allocator", 'b',
-     "use block allocator with size instead of garbage collection",
-     "<size in Kb>"},
-    {"aot-functions", 'a', "compile all functions to machine code", ""},
-    {"memory-usage", 'm',
-     "display the memory usage of parsing, compilation and the virtual "
-     "machine",
-     ""},
-    {"verbose", 'V', "verbose logging", ""},
-    {"run", 'r', "executes the argument as if an input file was given",
-     "<input>"},
-};
-
-void usage() {
-  Str prefix = STRING("usage: purple_garden");
-  printf("%.*s ", (int)prefix.len, prefix.p);
-  size_t len = sizeof(options) / sizeof(cli_option);
-  for (size_t i = 0; i < len; i++) {
-    const char *equal_or_not = options[i].arg_name[0] == 0 ? "" : "=";
-    const char *name_or_not =
-        options[i].arg_name[0] == 0 ? "" : options[i].arg_name;
-    printf("[-%c%s | --%s%s%s] ", options[i].name_short, name_or_not,
-           options[i].name_long, equal_or_not, name_or_not);
-    if ((i + 1) % 2 == 0 && i + 1 < len) {
-      printf("\n%*.s ", (int)prefix.len, "");
-    }
-  }
-  printf("<file.garden>\n");
-}
-
-// TODO: replace this shit with `6cl` - the purple garden and 6wm arguments
-// parser
 Args Args_parse(int argc, char **argv) {
-  Args a = (Args){0};
-  // MUST be in sync with options, otherwise this will not work as intended
-  struct option long_options[] = {
-      {options[0].name_long, no_argument, &a.version, 1},
-      {options[1].name_long, no_argument, &a.help, 1},
-      {options[2].name_long, no_argument, &a.disassemble, 1},
-      {options[3].name_long, required_argument, 0, 'b'},
-      {options[4].name_long, no_argument, &a.aot_functions, 1},
-      {options[5].name_long, no_argument, &a.memory_usage, 1},
-      {options[6].name_long, no_argument, &a.verbose, 1},
-      {options[7].name_long, required_argument, 0, 'r'},
-      {0, 0, 0, 0},
+  enum {
+    __VERSION,
+    __DISASSEMBLE,
+    __BLOCK_ALLOC,
+    __AOT,
+    __MEMORY_USAGE,
+    __VERBOSE,
+    __RUN,
   };
 
-  int opt;
-  while ((opt = getopt_long(argc, argv, "vhdb:amVr:", long_options, NULL)) !=
-         -1) {
-    switch (opt) {
-    case 'v':
-      a.version = 1;
-      break;
-    case 'V':
-      a.verbose = 1;
-      break;
-    case 'h':
-      a.help = 1;
-      break;
-    case 'd':
-      a.disassemble = 1;
-      break;
-    case 'r':
-      a.run = optarg;
-      break;
-    case 'b':
-      char *endptr;
-      size_t block_size = strtol(optarg, &endptr, 10);
-      ASSERT(endptr != optarg, "args: Failed to parse number from: %s", optarg);
-      a.block_allocator = block_size;
-      break;
-    case 'a':
-      a.aot_functions = 1;
-      break;
-    case 'm':
-      a.memory_usage = 1;
-      break;
-    case 0:
-      break;
-    default:
-      usage();
-      exit(EXIT_FAILURE);
-    }
-  }
-
-  if (optind < argc) {
-    a.filename = argv[optind];
+  SixFlag options[] = {
+      [__VERSION] = {.name = "version",
+                     .type = SIX_BOOL,
+                     .b = false,
+                     .short_name = 'v',
+                     .description = "display version information"},
+      [__DISASSEMBLE] =
+          {.name = "disassemble",
+           .short_name = 'd',
+           .type = SIX_BOOL,
+           .b = false,
+           .description =
+               "readable bytecode representation with labels, globals "
+               "and comments"},
+      [__BLOCK_ALLOC] =
+          {.name = "block-allocator",
+           .short_name = 'b',
+           .type = SIX_LONG,
+           .description =
+               "use block allocator with size instead of garbage collection"},
+      [__AOT] = {.name = "aot-functions",
+                 .short_name = 'a',
+                 .b = false,
+                 .type = SIX_BOOL,
+                 .description = "compile all functions to machine code"},
+      [__MEMORY_USAGE] = {.name = "memory-usage",
+                          .short_name = 'm',
+                          .b = false,
+                          .type = SIX_BOOL,
+                          .description = "display the memory usage of parsing, "
+                                         "compilation and the virtual "
+                                         "machine"},
+      [__VERBOSE] = {.name = "verbose",
+                     .short_name = 'V',
+                     .b = false,
+                     .type = SIX_BOOL,
+                     .description = "verbose logging"},
+      [__RUN] = {.name = "run",
+                 .short_name = 'r',
+                 .s = "",
+                 .type = SIX_STR,
+                 .description =
+                     "executes the argument as if an input file was given"},
+  };
+  Args a = (Args){0};
+  Six s = {
+      .flags = options,
+      .flag_count = sizeof(options) / sizeof(options[0]),
+      .name_for_rest_arguments = "<file.garden>",
+  };
+  SixParse(&s, argc, argv);
+  if (s.rest_count) {
+    a.filename = s.rest[0];
   }
+  a.block_allocator = s.flags[__BLOCK_ALLOC].l;
+  a.aot_functions = s.flags[__AOT].b;
+  a.disassemble = s.flags[__DISASSEMBLE].b;
+  a.memory_usage = s.flags[__MEMORY_USAGE].b;
+  a.run = s.flags[__RUN].s;
+  a.verbose = s.flags[__VERBOSE].b;
+  a.version = s.flags[__VERSION].b;
 
   // command handling
-  if (UNLIKELY(a.version)) {
+  if (a.version) {
     printf("purple_garden: %s-%s-%s\n", CTX, VERSION, COMMIT);
     if (UNLIKELY(a.verbose)) {
       puts(COMMIT_MSG);
     }
     exit(EXIT_SUCCESS);
-  } else if (UNLIKELY(a.help)) {
-    usage();
-    size_t len = sizeof(options) / sizeof(cli_option);
-    printf("\nOptions:\n");
-    for (size_t i = 0; i < len; i++) {
-      const char *equal_or_not = options[i].arg_name[0] == 0 ? "" : "=";
-      const char *name_or_not =
-          options[i].arg_name[0] == 0 ? "" : options[i].arg_name;
-      printf("\t-%c%s%s, --%s%s%s\n\t\t%s\n\n", options[i].name_short,
-             equal_or_not, name_or_not, options[i].name_long, equal_or_not,
-             name_or_not, options[i].description);
-    }
-    exit(EXIT_SUCCESS);
   }
 
-  if (UNLIKELY(a.filename == NULL && a.run == NULL)) {
-    usage();
+  if (a.filename == NULL && (a.run == NULL || a.run[0] == 0)) {
     fprintf(stderr, "error: Missing a file? try `-h/--help`\n");
     exit(EXIT_FAILURE);
   };
@@ -198,13 +140,14 @@ Args Args_parse(int argc, char **argv) {
 int main(int argc, char **argv) {
   struct timeval start_time, end_time;
   Args a = Args_parse(argc, argv);
+
   if (UNLIKELY(a.verbose)) {
     gettimeofday(&start_time, NULL);
   }
   VERBOSE_PUTS("main::Args_parse: Parsed arguments");
 
   Str input;
-  if (a.run != NULL) {
+  if (a.run != NULL && a.run[0] != 0) {
     input = (Str){.p = a.run, .len = strlen(a.run)};
   } else {
     input = IO_read_file_to_string(a.filename);
```

I am going to keep it real at this point, this doesn't feel as ergonomic as I
hoped. I still have to define an enum to make the option array order agnostic,
I have to define fields on a struct and i have to fill these fields on my own.

A better way would be a macro to generate the struct and the implementation
from a single source, but I'll keep it like this for now, the rest works great
and feels even better to maintain, especially the nice help page:

```text
$ ./purple_garden +h
usage ./purple_garden: [ +v / +version] [ +d / +disassemble]
                       [ +b / +block-allocator <long=0>] [ +a / +aot-functions]
                       [ +m / +memory-usage] [ +V / +verbose]
                       [ +r / +run <string=``>]
                       [ +h / +help] <file.garden>

Option:
          +v / +version
                display version information

          +d / +disassemble
                readable bytecode representation with labels, globals and comments

          +b / +block-allocator <long=0>
                use block allocator with size instead of garbage collection

          +a / +aot-functions
                compile all functions to machine code

          +m / +memory-usage
                display the memory usage of parsing, compilation and the virtual machine

          +V / +verbose
                verbose logging

          +r / +run <string=``>
                executes the argument as if an input file was given

          +h / +help
                help page and usage

Examples:
        ./purple_garden +v +d \
                        +b 0 +a \
                        +m +V \
                        +r ""

        ./purple_garden +version +disassemble \
                        +block-allocator 0 +aot-functions \
                        +memory-usage +verbose \
                        +run ""
```

## Extra: Ultra complicated error handling 

You probably noticed a lot of `goto err;` for all non happy path endings.

```c
err:
  usage(argv[0], six);
  exit(EXIT_FAILURE);
  return;
```

Since we do not do any heap allocations we don't have to clean anything up, the
return is just for good measure.
