use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use base64::Engine;
use tokio::sync::mpsc;

// Используем типы из нашей библиотеки
use crate::{
    register::{register, Registration},
    gcm::CheckedSession,
    push::{MessageStream, Message, new_heartbeat_ack},
    WebPushKeys,
    Session as GcmSession,
};

// Константы возврата
pub const FCM_SUCCESS: i32 = 0;
pub const FCM_ERROR_INVALID_PARAMS: i32 = -1;
pub const FCM_ERROR_NETWORK: i32 = -2;
pub const FCM_ERROR_AUTH: i32 = -3;
pub const FCM_ERROR_INTERNAL: i32 = -4;
pub const FCM_ERROR_NOT_FOUND: i32 = -5;
pub const FCM_ERROR_ALREADY_LISTENING: i32 = -6;

// C структура для регистрации
#[repr(C)]
pub struct CFcmRegistration {
    pub id: u64,
    pub fcm_token: *const c_char,
    pub android_id: i64,
    pub security_token: u64,
    pub auth_secret: *const c_char,
    pub private_key: *const c_char,
    pub public_key: *const c_char,
}

// C структура для push сообщения
#[repr(C)]
pub struct CFcmMessage {
    pub persistent_id: *const c_char,
    pub body: *const c_void,
    pub body_len: usize,
}

// C структура для создания регистрации из сохраненных данных
#[repr(C)]
pub struct CFcmRegistrationData {
    pub fcm_token: *const c_char,
    pub android_id: i64,
    pub security_token: u64,
    pub auth_secret: *const c_char,    // base64
    pub private_key: *const c_char,    // base64
    pub public_key: *const c_char,     // base64
}

// Типы callback'ов
pub type RegistrationCallback = extern "C" fn(i32, *const CFcmRegistration, *mut c_void);
pub type MessageCallback = extern "C" fn(*const CFcmMessage, *mut c_void);
pub type ErrorCallback = extern "C" fn(i32, *const c_char, *mut c_void);

// Структура для хранения состояния слушателя
struct ListenerState {
    registration: Registration,
    stop_sender: Option<mpsc::Sender<()>>,
    is_listening: bool,
}

// Глобальное хранилище регистраций и слушателей
static REGISTRATIONS: Mutex<HashMap<u64, Arc<Mutex<ListenerState>>>> = Mutex::new(HashMap::new());
static mut NEXT_ID: u64 = 1;

// Thread-local Runtime
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

// Инициализация библиотеки
#[no_mangle]
pub extern "C" fn fcm_init() -> i32 {
    match get_runtime() {
        Ok(()) => FCM_SUCCESS,
        Err(code) => code,
    }
}

// Очистка библиотеки
#[no_mangle]
pub extern "C" fn fcm_cleanup() {
    // Останавливаем все слушатели
    if let Ok(registrations) = REGISTRATIONS.lock() {
        for (_, state) in registrations.iter() {
            if let Ok(mut state) = state.lock() {
                if let Some(sender) = state.stop_sender.take() {
                    let _ = sender.blocking_send(());
                }
                state.is_listening = false;
            }
        }
    }
    
    RUNTIME.with(|runtime| {
        let mut rt = runtime.borrow_mut();
        *rt = None;
    });
    
    if let Ok(mut registrations) = REGISTRATIONS.lock() {
        registrations.clear();
    }
}

// Регистрация нового устройства
#[no_mangle]
pub extern "C" fn fcm_register_async(
    app_id: *const c_char,
    project_id: *const c_char,
    api_key: *const c_char,
    vapid_key: *const c_char, // может быть NULL
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
    
    let vapid_key = if vapid_key.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(vapid_key) }.to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => return FCM_ERROR_INVALID_PARAMS,
        }
    };

    std::thread::spawn(move || {
        get_runtime().ok();
        
        let result = RUNTIME.with(|runtime| {
            let rt = runtime.borrow();
            if let Some(ref rt) = *rt {
                rt.block_on(async {
                    let http = reqwest::Client::new();
                    register(&http, &app_id, &project_id, &api_key, vapid_key.as_deref()).await
                })
            } else {
                Err(crate::Error::DependencyFailure("runtime", "not initialized"))
            }
        });

        match result {
            Ok(registration) => {
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
                    let current_id = NEXT_ID;
                    NEXT_ID += 1;
                    current_id
                };

                let state = Arc::new(Mutex::new(ListenerState {
                    registration,
                    stop_sender: None,
                    is_listening: false,
                }));

                if let Ok(mut registrations) = REGISTRATIONS.lock() {
                    registrations.insert(id, state.clone());
                }

                let registration = state.lock().unwrap();
                let c_registration = CFcmRegistration {
                    id,
                    fcm_token: fcm_token_cstring.as_ptr(),
                    android_id: registration.registration.gcm.android_id,
                    security_token: registration.registration.gcm.security_token,
                    auth_secret: auth_secret_cstring.as_ptr(),
                    private_key: private_key_cstring.as_ptr(),
                    public_key: public_key_cstring.as_ptr(),
                };

                callback(FCM_SUCCESS, &c_registration, user_data);
            }
            Err(e) => {
                let error_msg = CString::new(format!("{}", e)).unwrap_or_default();
                callback(FCM_ERROR_NETWORK, std::ptr::null(), user_data);
                drop(error_msg);
            }
        }
    });

    FCM_SUCCESS
}

// Создание регистрации из сохраненных данных
#[no_mangle]
pub extern "C" fn fcm_create_registration_from_data(
    data: *const CFcmRegistrationData,
) -> u64 {
    if data.is_null() {
        return 0;
    }

    let data = unsafe { &*data };
    
    // Проверяем все указатели
    if data.fcm_token.is_null() || 
       data.auth_secret.is_null() || 
       data.private_key.is_null() || 
       data.public_key.is_null() {
        return 0;
    }

    // Парсим строки
    let fcm_token = match unsafe { CStr::from_ptr(data.fcm_token) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0,
    };
    
    let auth_secret_b64 = match unsafe { CStr::from_ptr(data.auth_secret) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    
    let private_key_b64 = match unsafe { CStr::from_ptr(data.private_key) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    
    let public_key_b64 = match unsafe { CStr::from_ptr(data.public_key) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Декодируем ключи из base64
    let auth_secret = match base64::engine::general_purpose::STANDARD.decode(auth_secret_b64) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    
    let private_key = match base64::engine::general_purpose::STANDARD.decode(private_key_b64) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    
    let public_key = match base64::engine::general_purpose::STANDARD.decode(public_key_b64) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // Создаем Registration
    let registration = Registration {
        fcm_token,
        gcm: GcmSession {
            android_id: data.android_id,
            security_token: data.security_token,
        },
        keys: WebPushKeys {
            auth_secret,
            private_key,
            public_key,
        },
    };

    // Генерируем ID и сохраняем
    let id = unsafe {
        let current_id = NEXT_ID;
        NEXT_ID += 1;
        current_id
    };

    let state = Arc::new(Mutex::new(ListenerState {
        registration,
        stop_sender: None,
        is_listening: false,
    }));

    if let Ok(mut registrations) = REGISTRATIONS.lock() {
        registrations.insert(id, state);
    }

    id
}

// Начать прослушивание push сообщений
#[no_mangle]
pub extern "C" fn fcm_start_listening(
    registration_id: u64,
    persistent_ids: *const *const c_char,
    persistent_ids_count: usize,
    message_callback: MessageCallback,
    error_callback: ErrorCallback,
    user_data: *mut c_void,
) -> i32 {
    let state = match REGISTRATIONS.lock() {
        Ok(registrations) => match registrations.get(&registration_id) {
            Some(state) => state.clone(),
            None => return FCM_ERROR_NOT_FOUND,
        },
        Err(_) => return FCM_ERROR_INTERNAL,
    };

    // Проверяем, не слушаем ли мы уже
    {
        let mut state_guard = match state.lock() {
            Ok(s) => s,
            Err(_) => return FCM_ERROR_INTERNAL,
        };
        
        if state_guard.is_listening {
            return FCM_ERROR_ALREADY_LISTENING;
        }
        state_guard.is_listening = true;
    }

    // Парсим persistent IDs
    let mut received_persistent_ids = Vec::new();
    if !persistent_ids.is_null() && persistent_ids_count > 0 {
        for i in 0..persistent_ids_count {
            let id_ptr = unsafe { *persistent_ids.add(i) };
            if !id_ptr.is_null() {
                if let Ok(id) = unsafe { CStr::from_ptr(id_ptr) }.to_str() {
                    received_persistent_ids.push(id.to_string());
                }
            }
        }
    }

    // Создаем канал для остановки
    let (stop_sender, mut stop_receiver) = mpsc::channel(1);
    
    {
        let mut state_guard = state.lock().unwrap();
        state_guard.stop_sender = Some(stop_sender);
    }

    std::thread::spawn(move || {
        get_runtime().ok();
        
        RUNTIME.with(|runtime| {
            let rt = runtime.borrow();
            if let Some(ref rt) = *rt {
                rt.block_on(async {
                    let registration = {
                        let state_guard = state.lock().unwrap();
                        state_guard.registration.clone()
                    };

                    let http = reqwest::Client::new();
                    
                    loop {
                        // Checkin
                        let session = match registration.gcm.checkin(&http).await {
                            Ok(s) => s,
                            Err(e) => {
                                let error_msg = CString::new(format!("Checkin failed: {}", e)).unwrap_or_default();
                                error_callback(FCM_ERROR_NETWORK, error_msg.as_ptr(), user_data);
                                break;
                            }
                        };

                        // Подключаемся
                        let connection = match session.new_connection(received_persistent_ids.clone()).await {
                            Ok(c) => c,
                            Err(e) => {
                                let error_msg = CString::new(format!("Connection failed: {}", e)).unwrap_or_default();
                                error_callback(FCM_ERROR_NETWORK, error_msg.as_ptr(), user_data);
                                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                                continue;
                            }
                        };

                        let mut stream = MessageStream::wrap(connection, &registration.keys);
                        
                        // Слушаем сообщения
                        loop {
                            use tokio_stream::StreamExt;
                            
                            tokio::select! {
                                _ = stop_receiver.recv() => {
                                    // Получили сигнал остановки
                                    break;
                                }
                                message = stream.next() => {
                                    match message {
                                        Some(Ok(Message::Data(data))) => {
                                            // Отправляем сообщение через callback
                                            let persistent_id_cstring = data.persistent_id
                                                .as_ref()
                                                .and_then(|id| CString::new(id.clone()).ok())
                                                .unwrap_or_default();
                                            
                                            let c_message = CFcmMessage {
                                                persistent_id: if data.persistent_id.is_some() { 
                                                    persistent_id_cstring.as_ptr() 
                                                } else { 
                                                    std::ptr::null() 
                                                },
                                                body: data.body.as_ptr() as *const c_void,
                                                body_len: data.body.len(),
                                            };

                                            message_callback(&c_message, user_data);
                                            
                                            // Добавляем ID в список полученных
                                            if let Some(id) = data.persistent_id {
                                                received_persistent_ids.push(id);
                                            }
                                        }
                                        Some(Ok(Message::HeartbeatPing)) => {
                                            // Отправляем heartbeat ack
                                            use tokio::io::AsyncWriteExt;
                                            let _ = stream.write_all(&new_heartbeat_ack()).await;
                                        }
                                        Some(Ok(Message::Other(_, _))) => {
                                            // Игнорируем другие сообщения
                                        }
                                        Some(Err(e)) => {
                                            let error_msg = CString::new(format!("Stream error: {}", e)).unwrap_or_default();
                                            error_callback(FCM_ERROR_NETWORK, error_msg.as_ptr(), user_data);
                                            break;
                                        }
                                        None => {
                                            // Соединение закрыто
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Проверяем, не остановлены ли мы
                        if stop_receiver.try_recv().is_ok() {
                            break;
                        }
                        
                        // Ждем перед переподключением
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                });
            }
        });
        
        // Отмечаем, что больше не слушаем
        if let Ok(mut state_guard) = state.lock() {
            state_guard.is_listening = false;
            state_guard.stop_sender = None;
        }
    });

    FCM_SUCCESS
}

// Остановить прослушивание
#[no_mangle]
pub extern "C" fn fcm_stop_listening(registration_id: u64) -> i32 {
    let state = match REGISTRATIONS.lock() {
        Ok(registrations) => match registrations.get(&registration_id) {
            Some(state) => state.clone(),
            None => return FCM_ERROR_NOT_FOUND,
        },
        Err(_) => return FCM_ERROR_INTERNAL,
    };

    let mut state_guard = match state.lock() {
        Ok(s) => s,
        Err(_) => return FCM_ERROR_INTERNAL,
    };
    
    if !state_guard.is_listening {
        return FCM_SUCCESS; // Уже остановлен
    }
    
    if let Some(sender) = state_guard.stop_sender.take() {
        let _ = sender.blocking_send(());
    }
    
    state_guard.is_listening = false;
    
    FCM_SUCCESS
}

// Получить FCM токен
#[no_mangle]
pub extern "C" fn fcm_get_token(registration_id: u64) -> *mut c_char {
    let state = match REGISTRATIONS.lock() {
        Ok(registrations) => match registrations.get(&registration_id) {
            Some(state) => state.clone(),
            None => return std::ptr::null_mut(),
        },
        Err(_) => return std::ptr::null_mut(),
    };

    let state_guard = match state.lock() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    
    match CString::new(state_guard.registration.fcm_token.clone()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// Получить Android ID
#[no_mangle]
pub extern "C" fn fcm_get_android_id(registration_id: u64) -> i64 {
    let state = match REGISTRATIONS.lock() {
        Ok(registrations) => match registrations.get(&registration_id) {
            Some(state) => state.clone(),
            None => return 0,
        },
        Err(_) => return 0,
    };

    let state_guard = match state.lock() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    
    state_guard.registration.gcm.android_id
}

// Получить Security Token
#[no_mangle]
pub extern "C" fn fcm_get_security_token(registration_id: u64) -> u64 {
    let state = match REGISTRATIONS.lock() {
        Ok(registrations) => match registrations.get(&registration_id) {
            Some(state) => state.clone(),
            None => return 0,
        },
        Err(_) => return 0,
    };

    let state_guard = match state.lock() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    
    state_guard.registration.gcm.security_token
}

// Удалить регистрацию
#[no_mangle]
pub extern "C" fn fcm_registration_free(registration_id: u64) -> i32 {
    // Сначала останавливаем слушатель, если он активен
    let _ = fcm_stop_listening(registration_id);
    
    // Удаляем из хранилища
    match REGISTRATIONS.lock() {
        Ok(mut registrations) => {
            registrations.remove(&registration_id);
            FCM_SUCCESS
        }
        Err(_) => FCM_ERROR_INTERNAL,
    }
}

// Освободить C строку
#[no_mangle]
pub extern "C" fn fcm_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}