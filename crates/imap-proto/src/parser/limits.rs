/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: how much one command may ask for.
//!
//! Each limit is well above what a client sends; a command past one is
//! refused with a tagged BAD. Without them a client that had signed in
//! could send one command, as long as the request size allows, that kept a
//! core busy or held much more memory than the command itself.

/// Sequence set items in one SEARCH, SORT or THREAD, over all of its sets.
/// Each item is checked against every message of the mailbox. One set is
/// already at most 8,000 bytes (the longest argument the receiver takes,
/// the line length RFC 2683 section 3.2.1.5 asks servers to accept), which
/// is at most 4,000 items, but a search can hold many sets.
pub const MAX_SEQUENCE_ITEMS: usize = 16_384;

/// Attributes in one FETCH. There are about 25 kinds; a client asking for
/// each part of a message on its own, with its MIME header, needs two per
/// part. The list is kept free of repeats, at a cost that grows with the
/// square of its length.
pub const MAX_FETCH_ATTRIBUTES: usize = 512;

/// Header field names in one FETCH, over all of its HEADER.FIELDS lists.
/// Each header of each message is compared with every name. Clients ask
/// for 10 to 40.
pub const MAX_FETCH_HEADER_FIELDS: usize = 1_024;

/// Search keys in one SEARCH, SORT or THREAD. Nesting is already limited
/// to ten levels.
pub const MAX_SEARCH_CRITERIA: usize = 1_024;

/// Flags in one STORE, or for one message of an APPEND.
pub const MAX_FLAGS: usize = 256;

#[cfg(test)]
mod tests {
    use crate::{
        Command,
        protocol::ProtocolVersion,
        receiver::{Receiver, Request},
    };

    fn request(line: String) -> Request<Command> {
        Receiver::<Command>::new()
            .parse(&mut line.as_bytes().iter())
            .unwrap_or_else(|err| panic!("{:.60}: {err:?}", line))
    }

    fn list(count: usize, item: impl Fn(usize) -> String, separator: &str) -> String {
        (1..=count).map(item).collect::<Vec<_>>().join(separator)
    }

    // A command at each limit parses; one item more is refused with BAD
    #[test]
    fn command_limits() {
        // Sequence set items, over all the sets of a SEARCH
        let set = |count| list(count, |i| (i * 2).to_string(), ",");
        let sets = |count| list(count, |_| set(1024), " ");
        assert!(
            request(format!("a SEARCH {}\r\n", sets(16)))
                .parse_search(ProtocolVersion::Rev2)
                .is_ok()
        );
        let err = request(format!("a SEARCH {} {}\r\n", sets(16), set(1)))
            .parse_search(ProtocolVersion::Rev2)
            .unwrap_err();
        assert_eq!(err.value_as_str(trc::Key::Id), Some("a"), "{err:?}");

        // FETCH attributes
        let sections = |count| list(count, |i| format!("BODY.PEEK[{i}]"), " ");
        assert!(
            request(format!("a FETCH 1 ({})\r\n", sections(512)))
                .parse_fetch()
                .is_ok()
        );
        assert!(
            request(format!("a FETCH 1 ({})\r\n", sections(513)))
                .parse_fetch()
                .is_err()
        );

        // Header field names, across the whole FETCH
        let fields = |count| list(count, |i| format!("X-H{i}"), " ");
        assert!(
            request(format!(
                "a FETCH 1 (BODY.PEEK[HEADER.FIELDS ({})] BODY.PEEK[1.HEADER.FIELDS ({})])\r\n",
                fields(512),
                fields(512)
            ))
            .parse_fetch()
            .is_ok()
        );
        assert!(
            request(format!(
                "a FETCH 1 (BODY.PEEK[HEADER.FIELDS ({})] BODY.PEEK[1.HEADER.FIELDS ({})])\r\n",
                fields(512),
                fields(513)
            ))
            .parse_fetch()
            .is_err()
        );

        // SEARCH criteria
        let criteria = |count| list(count, |i| format!("FROM a{i}"), " ");
        assert!(
            request(format!("a SEARCH {}\r\n", criteria(1024)))
                .parse_search(ProtocolVersion::Rev2)
                .is_ok()
        );
        assert!(
            request(format!("a SEARCH {}\r\n", criteria(1025)))
                .parse_search(ProtocolVersion::Rev2)
                .is_err()
        );
        assert!(
            request(format!("a UID SORT (DATE) UTF-8 {}\r\n", criteria(1025)))
                .parse_sort()
                .is_err()
        );

        // Flags in STORE and APPEND
        let flags = |count| list(count, |i| format!("$k{i}"), " ");
        assert!(
            request(format!("a STORE 1 +FLAGS ({})\r\n", flags(256)))
                .parse_store()
                .is_ok()
        );
        assert!(
            request(format!("a STORE 1 +FLAGS ({})\r\n", flags(257)))
                .parse_store()
                .is_err()
        );
        assert!(
            request(format!("a APPEND INBOX ({}) {{1+}}\r\na\r\n", flags(256)))
                .parse_append(false)
                .is_ok()
        );
        assert!(
            request(format!("a APPEND INBOX ({}) {{1+}}\r\na\r\n", flags(257)))
                .parse_append(false)
                .is_err()
        );
    }
}
