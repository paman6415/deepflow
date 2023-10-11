/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use public::l7_protocol::L7Protocol;
use serde::Serialize;

use super::super::{value_is_default, LogMessageType};

use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{FalseL7LogParser, L7ParseResult, L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        protocol_logs::{
            pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
            L7ResponseStatus,
        },
        AppProtoHead, Result,
    },
};

#[derive(Serialize, Debug, Default, Clone, PartialEq)]
pub struct OracleInfo {
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub is_tls: bool,

    // req
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub sql: String,
    #[serde(rename = "request_type")]
    pub data_id: u8,
    pub call_id: u8,

    // response
    pub ret_code: u16,
    #[serde(rename = "sql_affected_rows", skip_serializing_if = "value_is_default")]
    pub affected_rows: Option<u32>,
    #[serde(
        rename = "response_execption",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,

    pub rrt: u64,
}
impl OracleInfo {
    pub fn merge(&mut self, other: Self) {
        self.affected_rows = other.affected_rows;
        self.ret_code = other.ret_code;
        self.error_message = other.error_message;
        self.status = other.status;
    }

    fn get_req_type(&self) -> String {
        const DATA_ID_USER_OCI_FUNC: u8 = 0x03;
        const DATA_ID_PIGGY_BACK_FUNC: u8 = 0x11;

        const CALL_ID_CURSOR_CLOSE_ALL: u8 = 0x69;
        const CALL_ID_SWITCHING_PIGGYBACK: u8 = 0x6b;
        const CALL_ID_BUNDLED_EXE_ALL: u8 = 0x5e;

        match (self.data_id, self.call_id) {
            (DATA_ID_PIGGY_BACK_FUNC, CALL_ID_CURSOR_CLOSE_ALL)
            | (DATA_ID_PIGGY_BACK_FUNC, CALL_ID_SWITCHING_PIGGYBACK) => {
                "PIGGY_BACK_FUNC".to_string()
            }
            (DATA_ID_USER_OCI_FUNC, CALL_ID_BUNDLED_EXE_ALL) => "USER_OCI_FUNC".to_string(),
            _ => "".to_string(),
        }
    }
}

impl L7ProtocolInfoInterface for OracleInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::OracleInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Oracle,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }
}

impl From<OracleInfo> for L7ProtocolSendLog {
    fn from(f: OracleInfo) -> Self {
        let log = L7ProtocolSendLog {
            row_effect: f.affected_rows.unwrap_or_default(),
            req: L7Request {
                req_type: f.get_req_type(),
                resource: f.sql,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: Some(f.ret_code.into()),
                exception: f.error_message,
                ..Default::default()
            },
            ..Default::default()
        };
        return log;
    }
}

#[derive(Clone)]
pub struct OracleLog {
    parser: Box<dyn L7ProtocolParserInterface>,
}

impl Default for OracleLog {
    fn default() -> Self {
        Self {
            parser: Box::new(FalseL7LogParser {}),
        }
    }
}

impl L7ProtocolParserInterface for OracleLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        self.parser.check_payload(payload, param)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        self.parser.parse_payload(payload, param)
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Oracle
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.parser.perf_stats()
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
    fn is_extern(&self) -> bool {
        true
    }

    fn set_extern_parser(&mut self, log: Box<dyn L7ProtocolParserInterface>) {
        self.parser = log;
    }
}
