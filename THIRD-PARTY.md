# Third-party code

INBUXA is a fork of Stalwart. Stalwart is original work by Stalwart Labs LLC,
not a fork of anything, but a few of its files carry code, adapted or ported,
from other projects under permissive licenses. Those parts stay under their own
licenses, not the AGPL, and their notices are reproduced here as the licenses
require. Where a project offers MIT or Apache-2.0, INBUXA takes it under MIT.

`tools/fork/strip.py` lists every such file on each upstream import and names
any this page doesn't cover yet (docs/spec/SPEC.md §2.2). The fork's own code,
and Rust crates pulled in as dependencies, aren't listed here: dependencies
carry their own license files.

## Under the MIT license

| Where | From | Notice |
|---|---|---|
| `crates/common/src/scripts/functions/text.rs` | [levenshtein-rs](https://github.com/wooorm/levenshtein-rs) | Copyright (c) 2016 Titus Wormer <tituswormer@gmail.com> |
| `crates/common/src/telemetry/tracers/journald.rs` | the journald snippet | Copyright (c) 2018 Benjamin Saunders <ben.e.saunders@gmail.com> |
| `crates/jmap/src/registry/mapping/log.rs` | [rev_lines](https://github.com/mikeycgto/rev_lines) | Copyright (c) 2017 Michael Coyne <mjc@hey.com> |
| `crates/imap-proto/src/utf7.rs` | [MailKit](https://github.com/jstedfast/MailKit), by Jeffrey Stedfast | Copyright (C) 2013-2026 .NET Foundation and Contributors |
| `crates/nlp/src/tokenizers/japanese.rs` | [rust-tinysegmenter](https://github.com/woxtu/rust-tinysegmenter) | Copyright (c) 2015 woxtu |
| `crates/store/src/backend/postgres/tls.rs` | [tokio-postgres-rustls](https://github.com/jbg/tokio-postgres-rustls) | Copyright (c) 2019 Jasper Hugo |
| `crates/common/src/network/acme/directory.rs`, `crates/common/src/network/acme/jose.rs`, `crates/common/src/network/acme/order.rs` | [rustls-acme](https://github.com/FlorianUekermann/rustls-acme) (MIT or Apache-2.0) | Copyright (c) Florian Uekermann |
| `crates/types/src/id.rs` | [crockford](https://github.com/archer884/crockford) (MIT or Apache-2.0) | Copyright (c) 2017 J/A <archer884@gmail.com> |
| `crates/nlp/src/tokenizers/types.rs` | test cases from [linkify](https://github.com/robinst/linkify) (MIT or Apache-2.0) | Copyright (c) 2017 Robin Stocker |

Each notice above applies with this permission notice:

> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## Under the BSD 3-Clause license

| Where | From | Notice |
|---|---|---|
| `crates/jmap-proto/src/types/date.rs`, `crates/registry/src/types/datetime.rs` | [upb](https://github.com/protocolbuffers/upb/blob/22182e6e/upb/json_decode.c), the date parsing marked in each file | Copyright (c) 2009-2011, Google Inc. All rights reserved. |

```text
Copyright (c) 2009-2011, Google Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Google Inc. nor the names of any other
      contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY GOOGLE INC. ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL GOOGLE INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## Credited algorithms

These files implement published algorithms and credit their source. No code
is copied, so there's no notice to carry. They're listed so the strip report
doesn't flag them as new.

- `crates/jmap-proto/src/types/date.rs`, `crates/registry/src/types/datetime.rs`:
  `civil_from_days`, from Howard Hinnant's
  [date algorithms](http://howardhinnant.github.io/date_algorithms.html)
- `crates/utils/src/glob.rs`: Russ Cox's
  [glob matching](https://research.swtch.com/glob)
