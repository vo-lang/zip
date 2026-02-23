# vo-lang/zip

Vo wrapper for Rust `zip` for in-memory and directory archive operations.

## Module

```vo
import "github.com/vo-lang/zip"
```

## Implemented API

- `Pack(entries)`
- `PackFiles(entries)`
- `Unpack(data)`
- `ListNames(data)`
- `PackDir(inputDir, outputZip)`
- `UnpackToDir(inputZip, outputDir)`

## Build

```bash
cargo check --manifest-path rust/Cargo.toml
```
