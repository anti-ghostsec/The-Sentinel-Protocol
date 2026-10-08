//! Sentinel desktop entry point (the app itself is in lib.rs, shared with
//! the phone versions).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sentinel_app_lib::run()
}
