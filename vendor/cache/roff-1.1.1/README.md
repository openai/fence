# roff-rs

[![Documentation](https://img.shields.io/badge/docs-master-blue.svg)][Documentation]
![License](https://img.shields.io/crates/l/roff.svg)
[![crates.io](https://img.shields.io/crates/v/roff.svg)][Crates.io]

[Crates.io]: https://crates.io/crates/roff
[Documentation]: https://docs.rs/roff/

[Roff](http://man7.org/linux/man-pages/man7/roff.7.html) generation library.

## Examples

```rust
use roff::{bold, italic, roman, Roff};

fn main() {
    let page = Roff::new()
        .control("TH", ["CORRUPT", "1"])
        .control("SH", ["NAME"])
        .text([roman("corrupt - modify files by randomly changing bits")])
        .control("SH", ["SYNOPSIS"])
        .text([bold("corrupt"), roman(" ["), bold("-n"), roman(" "), italic("BITS"), roman("] ["),
               bold("--bits"), roman(" "), italic("BITS"), roman("] "), italic("FILE"), roman("..."),
        ])
        .control("SH", ["DESCRIPTION"])
        .text([bold("corrupt"), roman(" modifies files by toggling a randomly chosen bit.")])
        .control("SH", ["OPTIONS"])
        .control("TP", [])
        .text([bold("-n"), roman(", "), bold("--bits"), roman("="), italic("BITS")])
        .text([roman("Set the number of bits to modify. Default is one bit.")])
        .render();
    print!("{}", page);
}
```

Which outputs:
```troff
.ie \n(.g .ds Aq \(aq
.el .ds Aq '
.TH CORRUPT 1
.SH NAME
corrupt \- modify files by randomly changing bits
.SH SYNOPSIS
\fBcorrupt\fR [\fB\-n\fR \fIBITS\fR] [\fB\-\-bits\fR \fIBITS\fR] \fIFILE\fR...
.SH DESCRIPTION
\fBcorrupt\fR modifies files by toggling a randomly chosen bit.
.SH OPTIONS
.TP
\fB\-n\fR, \fB\-\-bits\fR=\fIBITS\fR
Set the number of bits to modify. Default is one bit.
```

Which will be shown by the `man(1)` command as:

```txt
CORRUPT(1)                 General Commands Manual                CORRUPT(1)

NAME
       corrupt - modify files by randomly changing bits

SYNOPSIS
       corrupt [-n BITS] [--bits BITS] FILE...

DESCRIPTION
       corrupt modifies files by toggling a randomly chosen bit.

OPTIONS
       -n, --bits=BITS
              Set the number of bits to modify. Default is one bit.

                                                                  CORRUPT(1)
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/license/mit>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
