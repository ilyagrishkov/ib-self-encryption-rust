use std::ffi::{c_void, CStr, CString};
use std::{mem, slice, str};
use std::os::raw::{c_char, c_int};
use libc::strlen;

#[no_mangle]
pub extern fn allocate(size: usize) -> *mut c_void {
    let mut buffer = Vec::with_capacity(size);
    let pointer = buffer.as_mut_ptr();
    mem::forget(buffer);

    pointer as *mut c_void
}

#[no_mangle]
pub extern fn deallocate(pointer: *mut c_void, capacity: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(pointer, 0, capacity);
    }
}

pub fn get_string(ptr: *mut c_char) -> String {
    let subject = unsafe { CStr::from_ptr(ptr).to_bytes().to_vec() };
    String::from_utf8(subject).unwrap()
}

pub fn get_string2(ptr: *mut c_char) -> String {
    let s = unsafe {
        println!("{}", strlen(ptr));
        str::from_utf8_unchecked(slice::from_raw_parts(ptr as *const u8, strlen(ptr)+1))
    };
    String::from(s)
}

pub fn get_byte_vec(ptr: *mut u8, size: usize) -> Vec<u8> {
    unsafe { Vec::from_raw_parts(ptr, size, size) }
}

pub fn return_byte_vec(mut return_vec: Vec<u8>, size_ptr: *mut c_char) -> *mut c_void {
    let length = return_vec.clone().len();
    let pointer = return_vec.as_mut_ptr();
    mem::forget(return_vec);

    unsafe { std::ptr::write(size_ptr, length as c_char); }

    pointer as *mut c_void
}

pub fn return_string(return_string: String) -> *mut c_char {
    unsafe { CString::from_vec_unchecked(Vec::from(return_string)) }.into_raw()
}