use std::io::{Cursor, Read, Write};
use std::collections::HashSet;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use serde_json::json;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

// ── Shared types ──────────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
struct Entry {
    name: String,
    data: Vec<u8>,
}

#[derive(Serialize)]
struct EntryInfo {
    name: String,
    compressed_size: i64,
    size: i64,
    is_dir: bool,
}

#[derive(Deserialize)]
struct PackReq {
    entries: Vec<Entry>,
}

struct ArchiveEntryData {
    name: String,
    compressed_size: i64,
    size: i64,
    is_dir: bool,
    data: Vec<u8>,
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn zip_options() -> SimpleFileOptions {
    SimpleFileOptions::default().compression_method(CompressionMethod::Deflated)
}

fn normalize_entry_name(name: &str) -> Result<String, String> {
    let normalized = name.replace('\\', "/");
    let mut parts = Vec::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("invalid zip entry path: {name}"));
            }
        }
    }
    if parts.is_empty() {
        return Err(format!("invalid zip entry path: {name}"));
    }
    Ok(parts.join("/"))
}

fn normalize_archive_entry_name(name: &str, is_dir: bool) -> Result<(String, String), String> {
    let normalized = normalize_entry_name(name)?;
    let display_name = if is_dir {
        format!("{normalized}/")
    } else {
        normalized.clone()
    };
    Ok((display_name, normalized))
}

fn insert_seen_name(seen: &mut HashSet<String>, name: &str) -> Result<(), String> {
    if !seen.insert(name.to_string()) {
        return Err(format!("duplicate zip entry path: {name}"));
    }
    Ok(())
}

fn collect_archive_entries_from_archive<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    include_dirs: bool,
    read_contents: bool,
) -> Result<Vec<ArchiveEntryData>, String> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
        let is_dir = file.is_dir();
        let (name, collision_name) = normalize_archive_entry_name(file.name(), is_dir)?;
        insert_seen_name(&mut seen, &collision_name)?;
        let compressed_size = i64::try_from(file.compressed_size())
            .map_err(|_| "compressed size out of range".to_string())?;
        let size = i64::try_from(file.size()).map_err(|_| "size out of range".to_string())?;
        let mut contents = Vec::new();
        if !is_dir && read_contents {
            file.read_to_end(&mut contents).map_err(|e| e.to_string())?;
        }
        if is_dir && !include_dirs {
            continue;
        }
        entries.push(ArchiveEntryData {
            name,
            compressed_size,
            size,
            is_dir,
            data: contents,
        });
    }
    Ok(entries)
}

fn collect_archive_entries(
    data: &[u8],
    include_dirs: bool,
    read_contents: bool,
) -> Result<Vec<ArchiveEntryData>, String> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| e.to_string())?;
    collect_archive_entries_from_archive(&mut archive, include_dirs, read_contents)
}

// ── Pure in-memory implementations (available to both native and wasm-standalone)

pub fn pack_impl(entries_json: &[u8]) -> Result<Vec<u8>, String> {
    let req: PackReq = serde_json::from_slice(entries_json).map_err(|e| e.to_string())?;
    let mut buf = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(&mut buf);
    let mut seen = HashSet::new();
    for e in req.entries {
        let name = normalize_entry_name(&e.name)?;
        insert_seen_name(&mut seen, &name)?;
        writer.start_file(name, zip_options()).map_err(|e| e.to_string())?;
        writer.write_all(&e.data).map_err(|e| e.to_string())?;
    }
    writer.finish().map_err(|e| e.to_string())?;
    Ok(buf.into_inner())
}

pub fn unpack_impl(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut entries = Vec::new();
    for entry in collect_archive_entries(data, false, true)? {
        entries.push(Entry { name: entry.name, data: entry.data });
    }
    serde_json::to_vec(&json!({ "entries": entries })).map_err(|e| e.to_string())
}

pub fn list_names_impl(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut names = Vec::new();
    for entry in collect_archive_entries(data, false, false)? {
        names.push(entry.name);
    }
    serde_json::to_vec(&json!({ "names": names })).map_err(|e| e.to_string())
}

pub fn list_entries_impl(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut entries = Vec::new();
    for entry in collect_archive_entries(data, true, false)? {
        entries.push(EntryInfo {
            name: entry.name,
            compressed_size: entry.compressed_size,
            size: entry.size,
            is_dir: entry.is_dir,
        });
    }
    serde_json::to_vec(&json!({ "entries": entries })).map_err(|e| e.to_string())
}

pub fn validate_impl(data: &[u8]) -> Result<(), String> {
    collect_archive_entries(data, true, false)?;
    Ok(())
}

// ── Native vo_fn bindings ─────────────────────────────────────────────────────

#[cfg(feature = "native")]
mod native {
    use super::*;
    use std::fs::{self, File};
    use std::path::PathBuf;
    use walkdir::WalkDir;
    use vo_ext::prelude::*;
    use vo_runtime::builtins::error_helper::{write_error_to, write_nil_error};

    fn rel_name(base: &Path, path: &Path) -> Result<String, String> {
        let rel = path.strip_prefix(base).map_err(|e| format!("strip prefix failed: {e}"))?;
        normalize_entry_name(&rel.to_string_lossy())
    }

    fn safe_out_path(base: &Path, name: &str) -> Result<PathBuf, String> {
        let normalized = normalize_entry_name(name)?;
        Ok(base.join(Path::new(&normalized)))
    }

    fn write_archive_entries_to_dir(base: &Path, entries: Vec<ArchiveEntryData>) -> Result<(), String> {
        fs::create_dir_all(base).map_err(|e| e.to_string())?;
        for entry in entries {
            let out_path = safe_out_path(base, &entry.name)?;
            if entry.is_dir {
                fs::create_dir_all(&out_path).map_err(|e| e.to_string())?;
                continue;
            }
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(&out_path, entry.data).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn pack_dir_impl(input_dir: &str, output_zip: &str) -> Result<(), String> {
        let input_dir = PathBuf::from(input_dir);
        let file = File::create(output_zip).map_err(|e| e.to_string())?;
        let mut writer = ZipWriter::new(file);
        for entry in WalkDir::new(&input_dir) {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.is_dir() { continue; }
            let name = rel_name(&input_dir, path)?;
            writer.start_file(name, zip_options()).map_err(|e| e.to_string())?;
            let mut f = File::open(path).map_err(|e| e.to_string())?;
            let mut data = Vec::new();
            f.read_to_end(&mut data).map_err(|e| e.to_string())?;
            writer.write_all(&data).map_err(|e| e.to_string())?;
        }
        writer.finish().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn unpack_to_dir_impl(input_zip: &str, output_dir: &str) -> Result<(), String> {
        let input = File::open(input_zip).map_err(|e| e.to_string())?;
        let mut archive = ZipArchive::new(input).map_err(|e| e.to_string())?;
        let entries = collect_archive_entries_from_archive(&mut archive, true, true)?;
        let out_dir = PathBuf::from(output_dir);
        write_archive_entries_to_dir(&out_dir, entries)
    }

    #[vo_fn("github.com/vo-lang/zip", "nativePack")]
    pub fn native_pack(call: &mut ExternCallContext) -> ExternResult {
        match pack_impl(call.arg_bytes(0)) {
            Ok(b) => { let r = call.alloc_bytes(&b); call.ret_ref(0, r); write_nil_error(call, 1); }
            Err(m) => { call.ret_nil(0); write_error_to(call, 1, &m); }
        }
        ExternResult::Ok
    }

    #[vo_fn("github.com/vo-lang/zip", "nativeUnpack")]
    pub fn native_unpack(call: &mut ExternCallContext) -> ExternResult {
        match unpack_impl(call.arg_bytes(0)) {
            Ok(b) => { let r = call.alloc_bytes(&b); call.ret_ref(0, r); write_nil_error(call, 1); }
            Err(m) => { call.ret_nil(0); write_error_to(call, 1, &m); }
        }
        ExternResult::Ok
    }

    #[vo_fn("github.com/vo-lang/zip", "nativeListNames")]
    pub fn native_list_names(call: &mut ExternCallContext) -> ExternResult {
        match list_names_impl(call.arg_bytes(0)) {
            Ok(b) => { let r = call.alloc_bytes(&b); call.ret_ref(0, r); write_nil_error(call, 1); }
            Err(m) => { call.ret_nil(0); write_error_to(call, 1, &m); }
        }
        ExternResult::Ok
    }

    #[vo_fn("github.com/vo-lang/zip", "nativeListEntries")]
    pub fn native_list_entries(call: &mut ExternCallContext) -> ExternResult {
        match list_entries_impl(call.arg_bytes(0)) {
            Ok(b) => { let r = call.alloc_bytes(&b); call.ret_ref(0, r); write_nil_error(call, 1); }
            Err(m) => { call.ret_nil(0); write_error_to(call, 1, &m); }
        }
        ExternResult::Ok
    }

    #[vo_fn("github.com/vo-lang/zip", "nativeValidate")]
    pub fn native_validate(call: &mut ExternCallContext) -> ExternResult {
        match validate_impl(call.arg_bytes(0)) {
            Ok(()) => write_nil_error(call, 0),
            Err(m) => write_error_to(call, 0, &m),
        }
        ExternResult::Ok
    }

    #[vo_fn("github.com/vo-lang/zip", "nativePackDir")]
    pub fn native_pack_dir(call: &mut ExternCallContext) -> ExternResult {
        match pack_dir_impl(call.arg_str(0), call.arg_str(1)) {
            Ok(()) => write_nil_error(call, 0),
            Err(m) => write_error_to(call, 0, &m),
        }
        ExternResult::Ok
    }

    #[vo_fn("github.com/vo-lang/zip", "nativeUnpackToDir")]
    pub fn native_unpack_to_dir(call: &mut ExternCallContext) -> ExternResult {
        match unpack_to_dir_impl(call.arg_str(0), call.arg_str(1)) {
            Ok(()) => write_nil_error(call, 0),
            Err(m) => write_error_to(call, 0, &m),
        }
        ExternResult::Ok
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::Value;
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        fn temp_dir(prefix: &str) -> PathBuf {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after unix epoch")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!("vo_zip_{prefix}_{nanos}"));
            fs::create_dir_all(&dir).expect("failed to create temp dir");
            dir
        }

        fn malicious_zip_bytes() -> Vec<u8> {
            let mut buf = Cursor::new(Vec::new());
            let mut writer = ZipWriter::new(&mut buf);
            writer.start_file("../escape.txt", zip_options())
                .expect("failed to write malicious entry");
            writer.write_all(b"boom").expect("failed to write malicious payload");
            writer.finish().expect("failed to finish malicious zip");
            buf.into_inner()
        }

        fn backslash_malicious_zip_bytes() -> Vec<u8> {
            let mut buf = Cursor::new(Vec::new());
            let mut writer = ZipWriter::new(&mut buf);
            writer.start_file("..\\escape.txt", zip_options())
                .expect("failed to write malicious backslash entry");
            writer.write_all(b"boom").expect("failed to write malicious backslash payload");
            writer.finish().expect("failed to finish malicious backslash zip");
            buf.into_inner()
        }

        fn colliding_name_zip_bytes() -> Vec<u8> {
            let mut buf = Cursor::new(Vec::new());
            let mut writer = ZipWriter::new(&mut buf);
            writer.start_file("nested/hello.txt", zip_options())
                .expect("failed to write first colliding entry");
            writer.write_all(b"first").expect("failed to write first colliding payload");
            writer.start_file("nested\\hello.txt", zip_options())
                .expect("failed to write second colliding entry");
            writer.write_all(b"second").expect("failed to write second colliding payload");
            writer.finish().expect("failed to finish colliding zip");
            buf.into_inner()
        }

        fn pack_request(entries: Value) -> Vec<u8> {
            serde_json::to_vec(&json!({ "entries": entries }))
                .expect("failed to build pack payload")
        }

        #[test]
        fn pack_unpack_and_list_roundtrip() {
            let req = pack_request(json!([
                {"name": "a.txt", "data": [65, 66]},
                {"name": "nested/b.txt", "data": [67]}
            ]));

            let zip_data = pack_impl(&req).expect("pack_impl should succeed");
            assert!(!zip_data.is_empty(), "zip data must not be empty");

            validate_impl(&zip_data).expect("validate_impl should pass for valid archive");

            let names_payload = list_names_impl(&zip_data).expect("list_names should succeed");
            let names_json: Value = serde_json::from_slice(&names_payload)
                .expect("names payload should be json");
            let names = names_json["names"].as_array().expect("names must be array");
            assert_eq!(names.len(), 2, "list_names should return two file names");

            let entries_payload = list_entries_impl(&zip_data).expect("list_entries should succeed");
            let entries_json: Value = serde_json::from_slice(&entries_payload)
                .expect("entries payload should be json");
            let entries = entries_json["entries"].as_array().expect("entries must be array");
            assert_eq!(entries.len(), 2, "list_entries should return two entries");

            let unpack_payload = unpack_impl(&zip_data).expect("unpack should succeed");
            let unpack_json: Value = serde_json::from_slice(&unpack_payload)
                .expect("unpack payload should be json");
            let unpack_entries = unpack_json["entries"].as_array()
                .expect("unpacked entries must be array");
            assert_eq!(unpack_entries.len(), 2, "unpack should return all packed entries");
        }

        #[test]
        fn pack_normalizes_entry_names_and_rejects_collisions() {
            let req = pack_request(json!([
                {"name": "nested\\hello.txt", "data": [65]}
            ]));

            let zip_data = pack_impl(&req).expect("pack_impl should normalize separators");
            let names_payload = list_names_impl(&zip_data).expect("list_names should succeed");
            let names_json: Value = serde_json::from_slice(&names_payload)
                .expect("names payload should be json");
            let names = names_json["names"].as_array().expect("names must be array");
            assert_eq!(names.len(), 1, "list_names should return one normalized entry");
            assert_eq!(names[0].as_str(), Some("nested/hello.txt"), "entry name should use forward slashes");

            let dup_req = pack_request(json!([
                {"name": "nested/hello.txt", "data": [65]},
                {"name": "nested\\hello.txt", "data": [66]}
            ]));
            assert!(pack_impl(&dup_req).is_err(), "pack_impl must reject duplicate normalized paths");
        }

        #[test]
        fn path_traversal_is_rejected() {
            let malicious = malicious_zip_bytes();
            assert!(validate_impl(&malicious).is_err(), "validate must reject parent-dir entries");
            assert!(unpack_impl(&malicious).is_err(), "unpack must reject parent-dir entries");

            let root = temp_dir("traversal");
            let zip_path = root.join("malicious.zip");
            fs::write(&zip_path, &malicious).expect("failed to write malicious zip file");

            let out_dir = root.join("out");
            let result = unpack_to_dir_impl(
                &zip_path.to_string_lossy(),
                &out_dir.to_string_lossy(),
            );
            assert!(result.is_err(), "unpack_to_dir must reject malicious traversal archive");

            let escaped = root.join("escape.txt");
            assert!(!escaped.exists(), "malicious entry must not create file outside output dir");

            fs::remove_dir_all(&root).expect("temp dir cleanup should succeed");
        }

        #[test]
        fn backslash_path_traversal_is_rejected() {
            let malicious = backslash_malicious_zip_bytes();
            assert!(validate_impl(&malicious).is_err(), "validate must reject backslash traversal entries");
            assert!(unpack_impl(&malicious).is_err(), "unpack must reject backslash traversal entries");

            let root = temp_dir("backslash-traversal");
            let zip_path = root.join("malicious.zip");
            fs::write(&zip_path, &malicious).expect("failed to write malicious backslash zip file");

            let out_dir = root.join("out");
            let result = unpack_to_dir_impl(
                &zip_path.to_string_lossy(),
                &out_dir.to_string_lossy(),
            );
            assert!(result.is_err(), "unpack_to_dir must reject backslash traversal archive");

            let escaped = root.join("escape.txt");
            assert!(!escaped.exists(), "backslash traversal entry must not create file outside output dir");

            fs::remove_dir_all(&root).expect("temp dir cleanup should succeed");
        }

        #[test]
        fn duplicate_normalized_paths_are_rejected_during_unpack_to_dir() {
            let colliding = colliding_name_zip_bytes();
            assert!(validate_impl(&colliding).is_err(), "validate must reject duplicate normalized paths");

            let root = temp_dir("duplicate-normalized");
            let zip_path = root.join("colliding.zip");
            fs::write(&zip_path, &colliding).expect("failed to write colliding zip file");

            let out_dir = root.join("out");
            let result = unpack_to_dir_impl(
                &zip_path.to_string_lossy(),
                &out_dir.to_string_lossy(),
            );
            assert!(result.is_err(), "unpack_to_dir must reject duplicate normalized paths");

            let written = out_dir.join("nested").join("hello.txt");
            assert!(!written.exists(), "duplicate normalized paths must not write any output file");

            fs::remove_dir_all(&root).expect("temp dir cleanup should succeed");
        }
    }
}

#[cfg(feature = "native")]
vo_ext::export_extensions!();

// ── Standalone C-ABI WASM exports ────────────────────────────────────────────
//
// Follows ext_bridge calling convention: fn(input_ptr, input_len, out_len_ptr) -> out_ptr
// Exports plain function names (e.g. "nativePack") — not path-prefixed.
// voCallExt in vo.ts resolves these via funcName lookup after stripping the module key.
// This keeps WASM exports decoupled from the module's GitHub path.

#[cfg(feature = "wasm-standalone")]
mod standalone {
    use super::{pack_impl, unpack_impl, list_names_impl, list_entries_impl, validate_impl};

    // v2 tagged protocol output tags (mirrors ext_bridge.rs constants)
    const TAG_NIL_ERROR: u8 = 0xE0;
    const TAG_ERROR_STR: u8 = 0xE1;
    const TAG_BYTES:     u8 = 0xE3;
    const TAG_NIL_REF:   u8 = 0xE4;

    #[no_mangle]
    pub extern "C" fn vo_alloc(size: u32) -> *mut u8 {
        let mut buf = Vec::<u8>::with_capacity(size as usize);
        let ptr = buf.as_mut_ptr();
        std::mem::forget(buf);
        ptr
    }

    #[no_mangle]
    pub extern "C" fn vo_dealloc(ptr: *mut u8, size: u32) {
        unsafe { drop(Vec::from_raw_parts(ptr, 0, size as usize)) };
    }

    fn alloc_output(data: &[u8], out_len: *mut u32) -> *mut u8 {
        unsafe { *out_len = data.len() as u32; }
        let ptr = vo_alloc(data.len() as u32);
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len()); }
        ptr
    }

    /// Decode the first [u32 LE len][bytes] entry from a tagged input buffer.
    fn read_bytes_arg(buf: &[u8]) -> &[u8] {
        if buf.len() < 4 { return &[]; }
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if 4 + len > buf.len() { return &buf[4..]; }
        &buf[4..4 + len]
    }

    /// Tagged output: success []byte + nil error  →  [0xE3][u32 len][bytes][0xE0]
    fn tagged_bytes_ok(data: &[u8], out_len: *mut u32) -> *mut u8 {
        let mut buf = Vec::with_capacity(5 + data.len() + 1);
        buf.push(TAG_BYTES);
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
        buf.push(TAG_NIL_ERROR);
        alloc_output(&buf, out_len)
    }

    /// Tagged output: nil []byte + error string  →  [0xE4][0xE1][u16 len][msg]
    fn tagged_bytes_err(msg: &str, out_len: *mut u32) -> *mut u8 {
        let mb = msg.as_bytes();
        let mlen = mb.len().min(0xFFFF) as u16;
        let mut buf = Vec::with_capacity(4 + mlen as usize);
        buf.push(TAG_NIL_REF);
        buf.push(TAG_ERROR_STR);
        buf.extend_from_slice(&mlen.to_le_bytes());
        buf.extend_from_slice(&mb[..mlen as usize]);
        alloc_output(&buf, out_len)
    }

    /// Tagged output: nil error only  →  [0xE0]
    fn tagged_nil_error(out_len: *mut u32) -> *mut u8 {
        alloc_output(&[TAG_NIL_ERROR], out_len)
    }

    /// Tagged output: error string only  →  [0xE1][u16 len][msg]
    fn tagged_error_only(msg: &str, out_len: *mut u32) -> *mut u8 {
        let mb = msg.as_bytes();
        let mlen = mb.len().min(0xFFFF) as u16;
        let mut buf = Vec::with_capacity(3 + mlen as usize);
        buf.push(TAG_ERROR_STR);
        buf.extend_from_slice(&mlen.to_le_bytes());
        buf.extend_from_slice(&mb[..mlen as usize]);
        alloc_output(&buf, out_len)
    }

    fn raw_input<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts(ptr, len as usize) }
    }

    #[no_mangle]
    pub extern "C" fn nativePack(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        let data = read_bytes_arg(raw_input(ptr, len));
        match pack_impl(data) {
            Ok(b)  => tagged_bytes_ok(&b, out_len),
            Err(e) => tagged_bytes_err(&e.to_string(), out_len),
        }
    }

    #[no_mangle]
    pub extern "C" fn nativeUnpack(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        let data = read_bytes_arg(raw_input(ptr, len));
        match unpack_impl(data) {
            Ok(b)  => tagged_bytes_ok(&b, out_len),
            Err(e) => tagged_bytes_err(&e.to_string(), out_len),
        }
    }

    #[no_mangle]
    pub extern "C" fn nativeListNames(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        let data = read_bytes_arg(raw_input(ptr, len));
        match list_names_impl(data) {
            Ok(b)  => tagged_bytes_ok(&b, out_len),
            Err(e) => tagged_bytes_err(&e.to_string(), out_len),
        }
    }

    #[no_mangle]
    pub extern "C" fn nativeListEntries(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        let data = read_bytes_arg(raw_input(ptr, len));
        match list_entries_impl(data) {
            Ok(b)  => tagged_bytes_ok(&b, out_len),
            Err(e) => tagged_bytes_err(&e.to_string(), out_len),
        }
    }

    #[no_mangle]
    pub extern "C" fn nativeValidate(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        let data = read_bytes_arg(raw_input(ptr, len));
        match validate_impl(data) {
            Ok(())  => tagged_nil_error(out_len),
            Err(e) => tagged_error_only(&e, out_len),
        }
    }

    // nativePackDir / nativeUnpackToDir require file system — not supported in WASM standalone.
    #[no_mangle]
    pub extern "C" fn nativePackDir(_ptr: *const u8, _len: u32, out_len: *mut u32) -> *mut u8 {
        tagged_bytes_err("nativePackDir: not supported in WASM", out_len)
    }

    #[no_mangle]
    pub extern "C" fn nativeUnpackToDir(_ptr: *const u8, _len: u32, out_len: *mut u32) -> *mut u8 {
        tagged_error_only("nativeUnpackToDir: not supported in WASM", out_len)
    }
}
