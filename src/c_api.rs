use std::ffi::{CStr, CString, c_char, c_void};
use std::collections::HashMap;
use std::sync::Mutex;
use base64::Engine; // Добавляем импорт для base64

// Используем типы из нашей библиотеки
use crate::register::{register, Registration};

// Константы возврата
pub const FCM_SUCCESS: i32 = 0;
pub const FCM_ERROR_INVALID_PARAMS: i32 = -1;
pub const FCM_ERROR_NETWORK: i32 = -2;
pub const FCM_ERROR_AUTH: i32 = -3;
pub const FCM_ERROR_INTERNAL: i32 = -4;

// C структуры
#[repr(C)]
pub struct CFcmRegistration {
    pub id: u64,
    pub android_id: i64,
    pub security_token: u64,
    pub fcm_token: *const c_char,
    pub auth_secret: *const c_char,
    pub private_key: *const c_char,
    pub public_key: *const c_char,
}

#[repr(C)]
pub struct CFcmMessage {
    pub persistent_id: *const c_char,
    pub body: *const c_void,
    pub body_len: usize,
}

// Типы callback'ов
pub type RegistrationCallback = extern "C" fn(i32, *const CFcmRegistration, *mut c_void);
pub type MessageCallback = extern "C" fn(*const CFcmMessage, *mut c_void);

// Глобальное хранилище регистраций
static REGISTRATIONS: Mutex<HashMap<u64, Registration>> = Mutex::new(HashMap::new());
static mut NEXT_ID: u64 = 1;

// Thread-local Runtime для избежания проблем с Send
thread_local! {
    static RUNTIME: std::cell::RefCell<Option<tokio::runtime::Runtime>> = 
        std::cell::RefCell::new(None);
}

fn get_runtime() -> Result<(), i32> {
    RUNTIME.with(|runtime| {
        let mut rt = runtime.borrow_mut();
        if rt.is_none() {
            *rt = Some(tokio::runtime::Runtime::new().map_err(|_| FCM_ERROR_INTERNAL)?);
        }
        Ok(())
    })
}

fn execute_async<F, Fut, T>(f: F) -> Result<T, i32>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    get_runtime()?;
    
    RUNTIME.with(|runtime| {
        let rt = runtime.borrow();
        if let Some(ref rt) = *rt {
            Ok(rt.block_on(f()))
        } else {
            Err(FCM_ERROR_INTERNAL)
        }
    })
}

#[no_mangle]
pub extern "C" fn fcm_init() -> i32 {
    match get_runtime() {
        Ok(()) => FCM_SUCCESS,
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn fcm_cleanup() {
    RUNTIME.with(|runtime| {
        let mut rt = runtime.borrow_mut();
        *rt = None;
    });
    
    if let Ok(mut registrations) = REGISTRATIONS.lock() {
        registrations.clear();
    }
}

#[no_mangle]
pub extern "C" fn fcm_register_async(
    app_id: *const c_char,
    project_id: *const c_char,
    api_key: *const c_char,
    callback: RegistrationCallback,
    user_data: *mut c_void,
) -> i32 {
    if app_id.is_null() || project_id.is_null() || api_key.is_null() {
        return FCM_ERROR_INVALID_PARAMS;
    }

    let app_id = match unsafe { CStr::from_ptr(app_id) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return FCM_ERROR_INVALID_PARAMS,
    };
    
    let project_id = match unsafe { CStr::from_ptr(project_id) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return FCM_ERROR_INVALID_PARAMS,
    };
    
    let api_key = match unsafe { CStr::from_ptr(api_key) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return FCM_ERROR_INVALID_PARAMS,
    };

    // Используем thread для избежания проблем с Send
    std::thread::spawn(move || {
        let result = execute_async(|| async {
            let http = reqwest::Client::new();
            register(&http, &app_id, &project_id, &api_key, None).await
        });

        match result {
            Ok(Ok(registration)) => {
                // Кодируем ключи в base64
                let auth_secret = base64::engine::general_purpose::STANDARD.encode(&registration.keys.auth_secret);
                let private_key = base64::engine::general_purpose::STANDARD.encode(&registration.keys.private_key);
                let public_key = base64::engine::general_purpose::STANDARD.encode(&registration.keys.public_key);

                // Создаем C строки
                let fcm_token_cstring = CString::new(registration.fcm_token.clone()).unwrap_or_default();
                let auth_secret_cstring = CString::new(auth_secret).unwrap_or_default();
                let private_key_cstring = CString::new(private_key).unwrap_or_default();
                let public_key_cstring = CString::new(public_key).unwrap_or_default();

                // Генерируем ID и сохраняем регистрацию
                let id = unsafe {
                    NEXT_ID += 1;
                    NEXT_ID
                };

                if let Ok(mut registrations) = REGISTRATIONS.lock() {
                    registrations.insert(id, registration.clone());
                }

                let c_registration = CFcmRegistration {
                    id,
                    android_id: registration.gcm.android_id,
                    security_token: registration.gcm.security_token,
                    fcm_token: fcm_token_cstring.as_ptr(),
                    auth_secret: auth_secret_cstring.as_ptr(),
                    private_key: private_key_cstring.as_ptr(),
                    public_key: public_key_cstring.as_ptr(),
                };

                callback(FCM_SUCCESS, &c_registration, user_data);
                
                // Освобождаем строки
                drop(fcm_token_cstring);
                drop(auth_secret_cstring);
                drop(private_key_cstring);
                drop(public_key_cstring);
            }
            _ => {
                callback(FCM_ERROR_NETWORK, std::ptr::null(), user_data);
            }
        }
    });

    FCM_SUCCESS
}

fn get_registration(id: u64) -> Option<Registration> {
    REGISTRATIONS.lock().ok()?.get(&id).cloned()
}

#[no_mangle]
pub extern "C" fn fcm_start_listening(
    registration_id: u64,
    callback: MessageCallback,
    user_data: *mut c_void,
) -> i32 {
    let _registration = match get_registration(registration_id) {
        Some(reg) => reg,
        None => return FCM_ERROR_INVALID_PARAMS,
    };

    std::thread::spawn(move || {
        // Заглушка для прослушивания сообщений - в реальной версии здесь будет полная реализация
        std::thread::sleep(std::chrono::Duration::from_secs(2));
        
        // Симулируем получение сообщения
        let body_content = r#"{"title": "Test Message", "body": "Hello from FCM!"}"#;
        let persistent_id_cstring = CString::new("msg_123").unwrap_or_default();
        
        let c_message = CFcmMessage {
            persistent_id: persistent_id_cstring.as_ptr(),
            body: body_content.as_ptr() as *const c_void,
            body_len: body_content.len(),
        };

        callback(&c_message, user_data);
        drop(persistent_id_cstring);
    });

    FCM_SUCCESS
}

#[no_mangle]
pub extern "C" fn fcm_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}
                    let c_message = CFcmMessage {
                        persistent_id: persistent_id_cstring.as_ptr(),
                        body: body.as_ptr() as *const c_void,
                        body_len: body.len(),
                    };

                    callback(&c_message, user_data);
                    drop(persistent_id_cstring);
                }
            }
            
            Ok::<(), Box<dyn std::error::Error>>(())
        });
        
        if let Err(_) = result {
            // Логируем ошибку или обрабатываем другим способом
        }
    });

    FCM_SUCCESS
}

#[no_mangle]
pub extern "C" fn fcm_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}