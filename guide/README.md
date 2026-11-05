# The LiteInst Guide (mdBook source)

Build locally:

```console
cargo install mdbook   # or fetch a release tarball; CI pins the version
mdbook build guide     # output in guide/book/
mdbook serve guide     # live preview
```

Conventions:

- Rust Book style: concept chapters alternate with project chapters;
  every listing names its source file; every project chapter ends with
  a runnable command and expected output.
- Unfinished or unimplemented material gets an Under construction box:

  ```markdown
  > 🚧 **Under construction — short title.** TODO: what is missing.
  > <!-- UC: short-id -->
  ```

  The `<!-- UC: ... -->` marker is the machine-countable record. The
  count on the Introduction page must always equal
  `grep -r --count '<!-- UC:' guide/src` summed over files; CI fails
  otherwise. The project goal is to drive the count to zero as the
  system and guide complete each other.
- Never upgrade a design or a subset implementation into a general
  claim. If the code refuses, the guide says it refuses.
- API detail belongs in rustdoc (docs.rs); the guide links to it
  rather than duplicating signatures.
