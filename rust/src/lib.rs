use std::io::{Cursor, Read, Write};
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

// ── Shared helpers ────────────────────────────────────────────────────────────

fn zip_options() -> SimpleFileOptions {
    SimpleFileOptions::default().compression_method(CompressionMethod::Deflated)
}

fn validate_entry_name(name: &str) -> Result<(), String> {
    let rel = Path::new(name);
    if rel.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(format!("invalid zip entry path: {name}"));
    }
    Ok(())
}

// ── Pure in-memory implementations (available to both native and wasm-standalone)

pub fn pack_impl(entries_json: &[u8]) -> Result<Vec<u8>, String> {
    let req: PackReq = serde_json::from_slice(entries_json).map_err(|e| e.to_string())?;
    let mut buf = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(&mut buf);
    for e in req.entries {
        validate_entry_name(&e.name)?;
        writer.start_file(e.name, zip_options()).map_err(|e| e.to_string())?;
        writer.write_all(&e.data).map_err(|e| e.to_string())?;
    }
    writer.finish().map_err(|e| e.to_string())?;
    Ok(buf.into_inner())
}

pub fn unpack_impl(data: &[u8]) -> Result<Vec<u8>, String> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| e.to_string())?;
    let mut entries = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
        if file.is_dir() { continue; }
        validate_entry_name(file.name())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).map_err(|e| e.to_string())?;
        entries.push(Entry { name: file.name().to_string(), data: contents });
    }
    serde_json::to_vec(&json!({ "entries": entries })).map_err(|e| e.to_string())
}

pub fn list_names_impl(data: &[u8]) -> Result<Vec<u8>, String> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| e.to_string())?;
    let mut names = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|e| e.to_string())?;
        if file.is_dir() { continue; }
        validate_entry_name(file.name())?;
        names.push(file.name().to_string());
    }
    serde_json::to_vec(&json!({ "names": names })).map_err(|e| e.to_string())
}

pub fn list_entries_impl(data: &[u8]) -> Result<Vec<u8>, String> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| e.to_string())?;
    let mut entries = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|e| e.to_string())?;
        validate_entry_name(file.name())?;
        let compressed_size = i64::try_from(file.compressed_size())
            .map_err(|_| "compressed size out of range".to_string())?;
        let size = i64::try_from(file.size()).map_err(|_| "size out of range".to_string())?;
        entries.push(EntryInfo {
            name: file.name().to_string(),
            compressed_size,
            size,
            is_dir: file.is_dir(),
        });
    }
    serde_json::to_vec(&json!({ "entries": entries })).map_err(|e| e.to_string())
}

pub fn validate_impl(data: &[u8]) -> Result<(), String> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| e.to_string())?;
    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|e| e.to_string())?;
        validate_entry_name(file.name())?;
    }
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
        Ok(rel.to_string_lossy().replace('\\', "/"))
    }

    fn safe_out_path(base: &Path, name: &str) -> Result<PathBuf, String> {
        validate_entry_name(name)?;
        Ok(base.join(Path::new(name)))
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
            validate_entry_name(&name)?;
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
        let out_dir = PathBuf::from(output_dir);
        fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
            let out_path = safe_out_path(&out_dir, file.name())?;
            if file.is_dir() {
                fs::create_dir_all(&out_path).map_err(|e| e.to_string())?;
                continue;
            }
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut out_file = File::create(&out_path).map_err(|e| e.to_string())?;
            std::io::copy(&mut file, &mut out_file).map_err(|e| e.to_string())?;
        }
        Ok(())
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
            Ok(()) => { call.ret_nil(0); write_nil_error(call, 1); }
            Err(m) => { call.ret_nil(0); write_error_to(call, 1, &m); }
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

        #[test]
        fn pack_unpack_and_list_roundtrip() {
            let req = serde_json::to_vec(&json!({
                "entries": [
                    {"name": "a.txt", "data": [65, 66]},
                    {"name": "nested/b.txt", "data": [67]}
                ]
            })).expect("failed to build pack payload");

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

    fn input_bytes<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts(ptr, len as usize) }
    }

    #[no_mangle]
    pub extern "C" fn nativePack(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        match pack_impl(input_bytes(ptr, len)) {
            Ok(b) => alloc_output(&b, out_len),
            Err(_) => { unsafe { *out_len = 0; } std::ptr::null_mut() }
        }
    }

    #[no_mangle]
    pub extern "C" fn nativeUnpack(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        match unpack_impl(input_bytes(ptr, len)) {
            Ok(b) => alloc_output(&b, out_len),
            Err(_) => { unsafe { *out_len = 0; } std::ptr::null_mut() }
        }
    }

    #[no_mangle]
    pub extern "C" fn nativeListNames(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        match list_names_impl(input_bytes(ptr, len)) {
            Ok(b) => alloc_output(&b, out_len),
            Err(_) => { unsafe { *out_len = 0; } std::ptr::null_mut() }
        }
    }

    #[no_mangle]
    pub extern "C" fn nativeListEntries(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        match list_entries_impl(input_bytes(ptr, len)) {
            Ok(b) => alloc_output(&b, out_len),
            Err(_) => { unsafe { *out_len = 0; } std::ptr::null_mut() }
        }
    }

    // nativeValidate returns only error. Return non-empty on success to signal no-error.
    #[no_mangle]
    pub extern "C" fn nativeValidate(ptr: *const u8, len: u32, out_len: *mut u32) -> *mut u8 {
        match validate_impl(input_bytes(ptr, len)) {
            Ok(()) => alloc_output(b"ok", out_len),
            Err(_) => { unsafe { *out_len = 0; } std::ptr::null_mut() }
        }
    }

    // nativePackDir / nativeUnpackToDir require file system — not supported in WASM standalone.
    #[no_mangle]
    pub extern "C" fn nativePackDir(_ptr: *const u8, _len: u32, out_len: *mut u32) -> *mut u8 {
        unsafe { *out_len = 0; }
        std::ptr::null_mut()
    }

    #[no_mangle]
    pub extern "C" fn nativeUnpackToDir(_ptr: *const u8, _len: u32, out_len: *mut u32) -> *mut u8 {
        unsafe { *out_len = 0; }
        std::ptr::null_mut()
    }
}
