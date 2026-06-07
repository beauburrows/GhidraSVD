# Changelog

All notable changes to this project are documented here.

## [Unreleased]

This release focuses on correctness of the generated register data types and on
robustness when importing real-world SVD files. Behaviour was cross-checked
against the original [leveldown SVD-Loader](https://github.com/leveldown-security/SVD-Loader-Ghidra)
and the [CMSIS-SVD specification](https://open-cmsis-pack.github.io/svd-spec/).

### Fixed

- **Registers narrower or wider than 32 bits were typed incorrectly.**
  `SvdDataTypesCreateTask.createRegisterDataType()` previously returned a fixed
  `UnsignedLongDataType` (4 bytes) for every field-less register, ignoring the
  register's declared `size`. Ghidra then constrained the component to a length
  that did not match the datatype, so:
  - 8-bit and 16-bit registers became malformed components (a 4-byte type forced
    into 1 or 2 bytes), corrupting the layout of adjacent registers;
  - 64-bit registers were silently truncated to 4 bytes, losing the upper word.

  Registers are now typed by their actual width using
  `AbstractIntegerDataType.getUnsignedDataType()` (`byte`/`word`/`dword`/`qword`
  for 1/2/4/8 bytes), restoring the size-aware behaviour the original
  leveldown script had. `Structure.replaceAtOffset()` is now called with a
  length of `-1` so the resolved fixed-length size is always used.
  *Why:* many Cortex-M peripherals expose 8-bit and 16-bit registers (timers,
  ADC, USB, GPIO half-words, etc.); mis-sizing them produced wrong structures
  and broke neighbouring fields, which is unacceptable for firmware reversing.

- **Peripherals with multiple address blocks duplicated and misplaced registers.**
  The data-type builder added every register whose offset was below a block's
  *size* to *every* block, using peripheral-relative offsets even though the
  struct is laid down at `base + block.offset`. Registers are now matched to a
  block's actual `[offset, offset + size)` window and stored at block-relative
  offsets. Registers that fall outside every declared block, or that extend past
  a block boundary, are reported instead of being silently dropped.
  *Why:* the previous logic only happened to work for the common
  single-block-at-offset-0 case and produced wrong layouts for multi-block or
  non-zero-offset peripherals.

- **Registers with fields could shrink below their true width.**
  Field-bearing registers are modelled as a packed structure, but packing
  recomputes the size from its contents, so registers whose high bits were
  reserved (no field) ended up shorter than the register. The bitfield base type
  now matches the register width (correct alignment) and any trailing reserved
  bits are padded, so the structure always equals the register's full size.
  *Why:* an under-sized register footprint leaves stray undefined bytes in the
  listing and misaligns everything placed after it.

### Changed

- **Each import task now runs in a single transaction.**
  `SvdDataTypesCreateTask` and the apply phase of `SvdMemoryMapUpdateTask`
  previously opened a separate transaction for nearly every operation (every
  label, every datatype, and each individual memory-block property change). They
  now wrap their work in one transaction each.
  *Why:* the old approach flooded the undo history with hundreds of tiny entries
  and was slow on large SVDs; a single transaction makes an import atomic and
  cleanly undoable.

- **Errors are reported instead of silently swallowed.**
  Numerous `catch` blocks that called `e.printStackTrace()` with an
  auto-generated TODO have been replaced. Failures are now logged through
  Ghidra's `Msg` facility, and `SvdDataTypesCreateTask` collects per-item
  problems (registers/fields it could not place) and surfaces them in a single
  summary dialog at the end of the run. A failure on one peripheral no longer
  aborts the rest of the import.
  *Why:* a reverse-engineering tool must be trustworthy — silently dropping a
  register to stderr hides exactly the information the user needs to know.

### Added

- **Field and register comments now include `access` and `enumeratedValues`.**
  When present in the SVD, a field's access type (e.g. read-only, write-only) and
  its full set of enumerated values (numeric value, name, and description) are
  written into the corresponding datatype comment; register comments include the
  register's access type.
  *Why:* access semantics and enumerated meanings are high-value context when
  reversing peripheral code, and the parser already exposes them — there is no
  reason to discard them.

- **Big-endian SVDs now raise a warning.**
  `SVDPlugin` checks the parsed CPU endianness after loading and warns the user
  when it is not little-endian, since the generated register datatypes assume a
  little-endian layout.
  *Why:* restores the intent of the original leveldown script's endianness check
  so silently-incorrect results on big-endian targets are flagged.

### Notes

- Interrupt definitions are parsed by the underlying library but are
  intentionally **not** turned into vector-table labels: the SVD does not carry
  the vector-table base address (that lives in VTOR / the binary), so placing
  labels would require guessing addresses. This was left out deliberately rather
  than risk silently-wrong output.
- No changes were required to the bundled `io.svdparser` library (v0.0.13); it
  already resolves peripheral `derivedFrom`, expands `dim` arrays for
  peripherals/registers/clusters, and flattens clusters into registers.
