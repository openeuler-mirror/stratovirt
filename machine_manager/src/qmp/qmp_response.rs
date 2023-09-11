// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::qmp_schema::{self as schema};

/// Qmp greeting message.
///
/// # Notes
///
/// It contains the version of VM or fake Qemu version to adapt others.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct QmpGreeting {
    #[serde(rename = "QMP")]
    qmp: Greeting,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
struct Greeting {
    version: Version,
    capabilities: Vec<String>,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct Version {
    #[serde(rename = "qemu")]
    application: VersionNumber,
    package: String,
}

impl Version {
    pub fn new(micro: u8, minor: u8, major: u8) -> Self {
        let version_number = VersionNumber {
            micro,
            minor,
            major,
        };
        Version {
            application: version_number,
            package: "StratoVirt-".to_string() + env!("CARGO_PKG_VERSION"),
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
struct VersionNumber {
    micro: u8,
    minor: u8,
    major: u8,
}

impl QmpGreeting {
    /// Create qmp greeting message.
    ///
    /// # Arguments
    ///
    /// * `micro` - Micro version number.
    /// * `minor` - Minor version number.
    /// * `major` - Major version number.
    pub(crate) fn create_greeting(micro: u8, minor: u8, major: u8) -> Self {
        let version = Version::new(micro, minor, major);
        let cap: Vec<String> = Default::default();
        let greeting = Greeting {
            version,
            capabilities: cap,
        };
        QmpGreeting { qmp: greeting }
    }
}

/// `ErrorMessage` for Qmp Response.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ErrorMessage {
    #[serde(rename = "class")]
    errorkind: String,
    desc: String,
}

impl ErrorMessage {
    fn new(e: &schema::QmpErrorClass) -> Self {
        let content = e.to_content();
        let serde_str = serde_json::to_string(&e).unwrap();
        let serde_vec: Vec<&str> = serde_str.split(':').collect();
        let class_name = serde_vec[0];
        let len: usize = class_name.len();
        ErrorMessage {
            errorkind: class_name[2..len - 1].to_string(),
            desc: content,
        }
    }
}

/// Empty message for QMP.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Empty {}

/// Qmp response to client
///
/// # Notes
///
/// It contains two kind response: `BadResponse` and `GoodResponse`. This two
/// kind response are fit by executing qmp command by success and failure.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    #[serde(rename = "return", default, skip_serializing_if = "Option::is_none")]
    return_: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<ErrorMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

impl Response {
    /// Create qmp response with inner `Value` and `id`.
    ///
    /// # Arguments
    ///
    /// * `v` - The `Value` of qmp `return` field.
    /// * `id` - The `id` for qmp `Response`, it must be equal to `Request`'s `id`.
    pub fn create_response(v: Value, id: Option<String>) -> Self {
        Response {
            return_: Some(v),
            error: None,
            id,
        }
    }

    /// Create a empty qmp response, `return` field will be empty.
    pub fn create_empty_response() -> Self {
        Response {
            return_: Some(serde_json::to_value(Empty {}).unwrap()),
            error: None,
            id: None,
        }
    }

    /// Create a error qmo response with `err_class` and `id`.
    /// # Arguments
    ///
    /// * `err_class` - The `QmpErrorClass` of qmp `error` field.
    /// * `id` - The `id` for qmp `Response`, it must be equal to `Request`'s `id`.
    pub fn create_error_response(err_class: schema::QmpErrorClass, id: Option<String>) -> Self {
        Response {
            return_: None,
            error: Some(ErrorMessage::new(&err_class)),
            id,
        }
    }

    pub(crate) fn change_id(&mut self, id: Option<String>) {
        self.id = id;
    }
}

impl From<bool> for Response {
    fn from(value: bool) -> Self {
        if value {
            Response::create_empty_response()
        } else {
            Response::create_error_response(
                schema::QmpErrorClass::GenericError(String::new()),
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json;

    use super::*;
    use crate::qmp::qmp_schema;

    #[test]
    fn test_qmp_greeting_msg() {
        let greeting_msg = QmpGreeting::create_greeting(1, 0, 5);

        let json_msg = r#"
            {
                "QMP":{
                    "version":{
                        "qemu":{
                            "micro": 1,
                            "minor": 0,
                            "major": 5
                        },
                        "package": "StratoVirt-2.3.0"
                    },
                    "capabilities": []
                }
            }
        "#;
        let greeting_from_json: QmpGreeting = serde_json::from_str(json_msg).unwrap();

        assert_eq!(greeting_from_json, greeting_msg);
    }

    #[test]
    fn test_qmp_resp() {
        // 1.Empty response and ID change;
        let mut resp = Response::create_empty_response();
        resp.change_id(Some("0".to_string()));

        let json_msg = r#"{"return":{},"id":"0"}"#;
        assert_eq!(serde_json::to_string(&resp).unwrap(), json_msg);

        resp.change_id(Some("1".to_string()));
        let json_msg = r#"{"return":{},"id":"1"}"#;
        assert_eq!(serde_json::to_string(&resp).unwrap(), json_msg);

        // 2.Normal response
        let resp_value = qmp_schema::StatusInfo {
            singlestep: false,
            running: true,
            status: qmp_schema::RunState::running,
        };
        let resp = Response::create_response(serde_json::to_value(&resp_value).unwrap(), None);

        let json_msg = r#"{"return":{"running":true,"singlestep":false,"status":"running"}}"#;
        assert_eq!(serde_json::to_string(&resp).unwrap(), json_msg);

        // 3.Error response
        let qmp_err =
            qmp_schema::QmpErrorClass::GenericError("Invalid Qmp command arguments!".to_string());
        let resp = Response::create_error_response(qmp_err, None);

        let json_msg =
            r#"{"error":{"class":"GenericError","desc":"Invalid Qmp command arguments!"}}"#;
        assert_eq!(serde_json::to_string(&resp).unwrap(), json_msg);
    }

    #[test]
    fn test_create_error_response() {
        let strange_msg = "!?/.,、。’】=  -~1！@#￥%……&*（）——+".to_string();

        let err_cls = qmp_schema::QmpErrorClass::GenericError(strange_msg.clone());
        let msg = ErrorMessage::new(&err_cls);
        assert_eq!(msg.desc, strange_msg);
        assert_eq!(msg.errorkind, "GenericError".to_string());
        let qmp_err = qmp_schema::QmpErrorClass::GenericError(strange_msg.clone());
        let resp = Response::create_error_response(qmp_err, None);
        assert_eq!(resp.error, Some(msg));

        let err_cls = qmp_schema::QmpErrorClass::CommandNotFound(strange_msg.clone());
        let msg = ErrorMessage::new(&err_cls);
        assert_eq!(msg.desc, strange_msg);
        assert_eq!(msg.errorkind, "CommandNotFound".to_string());
        let qmp_err = qmp_schema::QmpErrorClass::CommandNotFound(strange_msg.clone());
        let resp = Response::create_error_response(qmp_err, None);
        assert_eq!(resp.error, Some(msg));

        let err_cls = qmp_schema::QmpErrorClass::DeviceNotFound(strange_msg.clone());
        let msg = ErrorMessage::new(&err_cls);
        assert_eq!(msg.desc, strange_msg);
        assert_eq!(msg.errorkind, "DeviceNotFound".to_string());
        let qmp_err = qmp_schema::QmpErrorClass::DeviceNotFound(strange_msg.clone());
        let resp = Response::create_error_response(qmp_err, None);
        assert_eq!(resp.error, Some(msg));

        let err_cls = qmp_schema::QmpErrorClass::KVMMissingCap(strange_msg.clone());
        let msg = ErrorMessage::new(&err_cls);
        assert_eq!(msg.desc, strange_msg);
        assert_eq!(msg.errorkind, "KVMMissingCap".to_string());
        let qmp_err = qmp_schema::QmpErrorClass::KVMMissingCap(strange_msg.clone());
        let resp = Response::create_error_response(qmp_err, None);
        assert_eq!(resp.error, Some(msg));
    }
}
