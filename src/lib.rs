mod mcs {
    include!(concat!(env!("OUT_DIR"), "/mcs_proto.rs"));
}

mod error;
mod fcm;
mod firebase;
mod gcm;
mod push;
mod register;

pub use error::Error;
pub use fcm::WebPushKeys;
pub use gcm::Session;
pub use push::new_heartbeat_ack;
pub use push::DataMessage;
pub use push::Message;
pub use push::MessageStream;
pub use push::MessageTag;
pub use register::register;
pub use register::Registration;

// C API модуль включается только при feature ffi
#[cfg(feature = "ffi")]
pub mod c_api;