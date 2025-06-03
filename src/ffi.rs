use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::{register, Registration};

// Add this to your src/lib.rs:
// #[cfg(feature = "ffi")]
// pub mod ffi;

/// Result type for FFI operations
/// 
/// cbindgen:field-names=[success, error_message, data]
#[repr(C)]
pub struct FfiResult {
    /// Whether the operation succeeded
    pub success: bool,
    /// Error message if operation failed (null if success)
    /// Must be freed with fcm_string_free
    pub error_message: *mut c_char,
    /// Opaque pointer to result data (null if failed)
    pub data: *mut std::ffi::c_void,
}

/// Opaque registration handle
/// 
/// cbindgen:opaque
pub struct FfiRegistration {
    inner: Registration,
}

/// Register with FCM and return a handle to the registration
#[no_mangle]
pub extern "C" fn fcm_register(
    firebase_app_id: *const c_char,
    firebase_project_id: *const c_char,
    firebase_api_key: *const c_char,
    vapid_key: *const c_char, // can be null
) -> FfiResult {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult {
                success: false,
                error_message: CString::new(format!("Failed to create runtime: {}", e))
                    .unwrap()
                    .into_raw(),
                data: ptr::null_mut(),
            }
        }
    };

    // Convert C strings to Rust strings
    let app_id = unsafe {
        if firebase_app_id.is_null() {
            return FfiResult {
                success: false,
                error_message: CString::new("firebase_app_id is null").unwrap().into_raw(),
                data: ptr::null_mut(),
            };
        }
        CStr::from_ptr(firebase_app_id).to_string_lossy().into_owned()
    };

    let project_id = unsafe {
        if firebase_project_id.is_null() {
            return FfiResult {
                success: false,
                error_message: CString::new("firebase_project_id is null").unwrap().into_raw(),
                data: ptr::null_mut(),
            };
        }
        CStr::from_ptr(firebase_project_id).to_string_lossy().into_owned()
    };

    let api_key = unsafe {
        if firebase_api_key.is_null() {
            return FfiResult {
                success: false,
                error_message: CString::new("firebase_api_key is null").unwrap().into_raw(),
                data: ptr::null_mut(),
            };
        }
        CStr::from_ptr(firebase_api_key).to_string_lossy().into_owned()
    };

    let vapid = if vapid_key.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(vapid_key).to_string_lossy().into_owned() })
    };

    // Run the async registration
    let result = runtime.block_on(async {
        let http = reqwest::Client::new();
        register(
            &http,
            &app_id,
            &project_id,
            &api_key,
            vapid.as_deref(),
        )
        .await
    });

    match result {
        Ok(registration) => {
            let ffi_reg = Box::new(FfiRegistration { inner: registration });
            FfiResult {
                success: true,
                error_message: ptr::null_mut(),
                data: Box::into_raw(ffi_reg) as *mut std::ffi::c_void,
            }
        }
        Err(e) => FfiResult {
            success: false,
            error_message: CString::new(format!("Registration failed: {}", e))
                .unwrap()
                .into_raw(),
            data: ptr::null_mut(),
        },
    }
}

/// Get the FCM token from a registration
#[no_mangle]
pub extern "C" fn fcm_get_token(registration: *const FfiRegistration) -> *mut c_char {
    if registration.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let reg = &*registration;
        match CString::new(reg.inner.fcm_token.clone()) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }
}

/// Free a registration handle
#[no_mangle]
pub extern "C" fn fcm_registration_free(registration: *mut FfiRegistration) {
    if !registration.is_null() {
        unsafe {
            let _ = Box::from_raw(registration);
        }
    }
}

/// Free a C string returned by this library
#[no_mangle]
pub extern "C" fn fcm_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Free an FfiResult error message
#[no_mangle]
pub extern "C" fn fcm_result_free(result: FfiResult) {
    if !result.error_message.is_null() {
        unsafe {
            let _ = CString::from_raw(result.error_message);
        }
    }
}