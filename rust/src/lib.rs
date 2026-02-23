use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[cfg(feature = "native")]
mod native {
    use super::*;
    use vo_ext::prelude::*;
    use vo_runtime::builtins::error_helper::{write_error_to, write_nil_error};

    #[derive(Deserialize, Serialize)]
    struct Entry {
        name: String,
        data: Vec<u8>,
    }

    #[derive(Deserialize)]
    struct PackReq {
        entries: Vec<Entry>,
    }

    #[derive(Deserialize)]
    struct UnpackReq {
        data: Vec<u8>,
    }

    #[derive(Deserialize)]
    struct PackDirReq {
        input_dir: String,
        output_zip: String,
    }

    #[derive(Deserialize)]
    struct UnpackToDirReq {
        input_zip: String,
        output_dir: String,
    }

    fn empty_ok() -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn zip_options() -> SimpleFileOptions {
        SimpleFileOptions::default().compression_method(CompressionMethod::Deflated)
    }

    fn handle_pack(input: &str) -> Result<Vec<u8>, String> {
        let req: PackReq = serde_json::from_str(input).map_err(|e| e.to_string())?;
        let mut buf = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(&mut buf);
        for e in req.entries {
            validate_entry_name(&e.name)?;
            writer
                .start_file(e.name, zip_options())
                .map_err(|e| e.to_string())?;
            writer.write_all(&e.data).map_err(|e| e.to_string())?;
        }
        writer.finish().map_err(|e| e.to_string())?;
        Ok(buf.into_inner())
    }

    fn handle_unpack(input: &str) -> Result<Vec<u8>, String> {
        let req: UnpackReq = serde_json::from_str(input).map_err(|e| e.to_string())?;
        let cursor = Cursor::new(req.data);
        let mut archive = ZipArchive::new(cursor).map_err(|e| e.to_string())?;

        let mut entries = Vec::new();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
            if file.is_dir() {
                continue;
            }
            validate_entry_name(file.name())?;
            let mut data = Vec::new();
            file.read_to_end(&mut data).map_err(|e| e.to_string())?;
            entries.push(Entry {
                name: file.name().to_string(),
                data,
            });
        }

        serde_json::to_vec(&json!({ "entries": entries })).map_err(|e| e.to_string())
    }

    fn handle_list_names(input: &str) -> Result<Vec<u8>, String> {
        let req: UnpackReq = serde_json::from_str(input).map_err(|e| e.to_string())?;
        let cursor = Cursor::new(req.data);
        let mut archive = ZipArchive::new(cursor).map_err(|e| e.to_string())?;

        let mut names = Vec::new();
        for i in 0..archive.len() {
            let file = archive.by_index(i).map_err(|e| e.to_string())?;
            if file.is_dir() {
                continue;
            }
            validate_entry_name(file.name())?;
            names.push(file.name().to_string());
        }

        serde_json::to_vec(&json!({ "names": names })).map_err(|e| e.to_string())
    }

    fn rel_name(base: &Path, path: &Path) -> Result<String, String> {
        let rel = path
            .strip_prefix(base)
            .map_err(|e| format!("strip prefix failed: {e}"))?;
        Ok(rel.to_string_lossy().replace('\\', "/"))
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

    fn safe_out_path(base: &Path, name: &str) -> Result<PathBuf, String> {
        validate_entry_name(name)?;
        let rel = Path::new(name);
        Ok(base.join(rel))
    }

    fn handle_pack_dir(input: &str) -> Result<Vec<u8>, String> {
        let req: PackDirReq = serde_json::from_str(input).map_err(|e| e.to_string())?;
        let input_dir = PathBuf::from(&req.input_dir);
        let file = File::create(&req.output_zip).map_err(|e| e.to_string())?;
        let mut writer = ZipWriter::new(file);

        for entry in WalkDir::new(&input_dir) {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let name = rel_name(&input_dir, path)?;
            validate_entry_name(&name)?;
            writer
                .start_file(name, zip_options())
                .map_err(|e| e.to_string())?;
            let mut f = File::open(path).map_err(|e| e.to_string())?;
            let mut data = Vec::new();
            f.read_to_end(&mut data).map_err(|e| e.to_string())?;
            writer.write_all(&data).map_err(|e| e.to_string())?;
        }

        writer.finish().map_err(|e| e.to_string())?;
        empty_ok()
    }

    fn handle_unpack_to_dir(input: &str) -> Result<Vec<u8>, String> {
        let req: UnpackToDirReq = serde_json::from_str(input).map_err(|e| e.to_string())?;
        let input = File::open(&req.input_zip).map_err(|e| e.to_string())?;
        let mut archive = ZipArchive::new(input).map_err(|e| e.to_string())?;
        let out_dir = PathBuf::from(&req.output_dir);
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

        empty_ok()
    }

    fn dispatch(op: &str, input: &str) -> Result<Vec<u8>, String> {
        match op {
            "pack" => handle_pack(input),
            "unpack" => handle_unpack(input),
            "list_names" => handle_list_names(input),
            "pack_dir" => handle_pack_dir(input),
            "unpack_to_dir" => handle_unpack_to_dir(input),
            _ => Err(format!("unsupported operation: {op}")),
        }
    }

    #[vo_fn("github.com/vo-lang/zip", "RawCall")]
    pub fn raw_call(call: &mut ExternCallContext) -> ExternResult {
        let op = call.arg_str(0);
        let input = call.arg_str(1);

        match dispatch(op, input) {
            Ok(bytes) => {
                let out_ref = call.alloc_bytes(&bytes);
                call.ret_ref(0, out_ref);
                write_nil_error(call, 1);
            }
            Err(msg) => {
                call.ret_nil(0);
                write_error_to(call, 1, &msg);
            }
        }

        ExternResult::Ok
    }
}

#[cfg(feature = "native")]
vo_ext::export_extensions!();
