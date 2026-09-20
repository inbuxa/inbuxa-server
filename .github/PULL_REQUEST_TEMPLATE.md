<!--
  Thanks for contributing to INBUXA. CONTRIBUTING.md has the full guide; this
  is the short version. Delete any section that does not apply.
-->

## Summary

<!-- What changes, and why. The why is the part that is hard to recover later. -->

## Related issues

<!-- e.g. Closes #123. Leave blank if there are none. -->

## Upstream files

<!--
  Does this touch files that came from Stalwart? If so: is the change as small
  as it can be, and is it marked with an `inbuxa:` comment saying which
  requirement it serves? Every edit to an upstream file is a conflict waiting
  at the next import, so it should be worth one.
-->

## Clean room

<!--
  Only for changes to the rebuilt features in `crates/features`, or to the
  hooks that serve them.

  Confirm one:
  - [ ] I have not read Stalwart's Enterprise-licensed source, and worked from
        the specification in `docs/spec/features/`.
  - [ ] I have read it. (Say so -- the change will be reviewed with that in
        mind, or declined for the parts it touches. The project's claim of
        independent creation is a record, and the record has to be true.)
-->

## Testing

<!--
  What you ran. `cargo test -p tests` covers what needs nothing but a store;
  say so if you ran any of the `#[ignore]`d suites from
  docs/spec/container-tests.md, and which.
-->
