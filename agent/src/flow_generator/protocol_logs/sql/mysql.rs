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

mod comment_parser;

use serde::Serialize;

use super::super::{consts::*, value_is_default, AppProtoHead, L7ResponseStatus, LogMessageType};
use super::sql_check::{check_sql, is_mysql, trim_head_comment_and_get_first_word};

use crate::common::flow::L7PerfStats;
use crate::common::l7_protocol_log::L7ParseResult;
use crate::flow_generator::protocol_logs::pb_adapter::TraceInfo;
use crate::{
    common::{
        enums::IpProtocol,
        flow::L7Protocol,
        flow::PacketDirection,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    flow_generator::{
        error::{Error, Result},
        protocol_logs::pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
    },
    utils::bytes,
};
use public::bytes::read_u32_le;

#[derive(Serialize, Debug, Default, Clone)]
pub struct MysqlInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    // Server Greeting
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub protocol_version: u8,
    #[serde(skip)]
    pub server_version: String,
    #[serde(skip)]
    pub server_thread_id: u32,
    // request
    #[serde(rename = "request_type")]
    pub command: u8,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub context: String,
    // response
    pub response_code: u8,
    #[serde(skip)]
    pub error_code: Option<i32>,
    #[serde(rename = "sql_affected_rows", skip_serializing_if = "value_is_default")]
    pub affected_rows: u64,
    #[serde(
        rename = "response_execption",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,

    rrt: u64,
    // This field is extracted in the following message:
    // 1. Response message corresponding to COM_STMT_PREPARE request
    // 2. COM_STMT_EXECUTE request message
    statement_id: u32,

    trace_id: Option<String>,
}

impl L7ProtocolInfoInterface for MysqlInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::MysqlInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::MySQL,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }
}

impl MysqlInfo {
    pub fn merge(&mut self, other: Self) {
        if self.protocol_version == 0 {
            self.protocol_version = other.protocol_version
        }
        match other.msg_type {
            LogMessageType::Request => {
                self.command = other.command;
                self.context = other.context;
            }
            LogMessageType::Response => {
                self.response_code = other.response_code;
                self.affected_rows = other.affected_rows;
                self.error_message = other.error_message;
                self.status = other.status;
                if self.error_code.is_none() {
                    self.error_code = other.error_code;
                }
                if self.command == COM_STMT_PREPARE && other.statement_id > 0 {
                    self.statement_id = other.statement_id;
                } else {
                    self.statement_id = 0;
                }
            }
            _ => {}
        }
    }

    pub fn get_command_str(&self) -> &'static str {
        let command = [
            "", // command 0 is resp, ignore
            "COM_QUIT",
            "COM_INIT_DB",
            "COM_QUERY",
            "COM_FIELD_LIST",
            "COM_CREATE_DB",
            "COM_DROP_DB",
            "COM_REFRESH",
            "COM_SHUTDOWN",
            "COM_STATISTICS",
            "COM_PROCESS_INFO",
            "COM_CONNECT",
            "COM_PROCESS_KILL",
            "COM_DEBUG",
            "COM_PING",
            "COM_TIME",
            "COM_DELAYED_INSERT",
            "COM_CHANGE_USER",
            "COM_BINLOG_DUMP",
            "COM_TABLE_DUMP",
            "COM_CONNECT_OUT",
            "COM_REGISTER_SLAVE",
            "COM_STMT_PREPARE",
            "COM_STMT_EXECUTE",
            "COM_STMT_SEND_LONG_DATA",
            "COM_STMT_CLOSE",
            "COM_STMT_RESET",
            "COM_SET_OPTION",
            "COM_STMT_FETCH",
            "COM_DAEMON",
            "COM_BINLOG_DUMP_GTID",
            "COM_RESET_CONNECTION",
        ];
        match self.command {
            0x00..=0x1f => command[self.command as usize],
            _ => "",
        }
    }

    fn request_string(&mut self, payload: &[u8], trace_id: Option<&str>) {
        self.context = mysql_string(payload);
        if let Some(t) = trace_id {
            self.trace_id = extra_sql_trace_id(self.context.as_str(), t);
        }
    }

    fn statement_id(&mut self, payload: &[u8]) {
        if payload.len() >= STATEMENT_ID_LEN {
            self.statement_id = read_u32_le(payload)
        }
    }
}

impl From<MysqlInfo> for L7ProtocolSendLog {
    fn from(f: MysqlInfo) -> Self {
        let flags = if f.is_tls {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };
        let log = L7ProtocolSendLog {
            version: if f.protocol_version == 0 {
                None
            } else {
                Some(f.protocol_version.to_string())
            },

            row_effect: if f.command == COM_QUERY {
                trim_head_comment_and_get_first_word(&f.context, 8)
                    .map(|first| {
                        if check_sql(first, &["INSERT", "UPDATE", "DELETE"]) {
                            f.affected_rows as u32
                        } else {
                            0
                        }
                    })
                    .unwrap_or_default()
            } else {
                0
            },
            req: L7Request {
                req_type: String::from(f.get_command_str()),
                resource: f.context,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: f.error_code,
                exception: f.error_message,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: f.statement_id.into(),
                ..Default::default()
            }),
            trace_info: if f.trace_id.is_some() {
                Some(TraceInfo {
                    trace_id: f.trace_id,
                    ..Default::default()
                })
            } else {
                None
            },
            flags,
            ..Default::default()
        };
        return log;
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MysqlLog {
    pub protocol_version: u8,
    #[serde(skip)]
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for MysqlLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        Self::check(payload, param)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut info = MysqlInfo::default();
        info.protocol_version = self.protocol_version;
        info.is_tls = param.is_tls();
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        if self.parse(
            payload,
            param.l4_protocol,
            param.direction,
            param.parse_config.and_then(|c| {
                for i in c.l7_log_dynamic.trace_types.iter() {
                    match i {
                        crate::config::handler::TraceType::Customize(c) => return Some(c.as_str()),
                        _ => continue,
                    }
                }
                None
            }),
            &mut info,
        )? {
            // ignore greeting
            return Ok(L7ParseResult::None);
        }
        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::MysqlInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::MySQL
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

fn mysql_string(payload: &[u8]) -> String {
    if payload.len() > 2 && payload[0] == 0 && payload[1] == 1 {
        // MYSQL 8.0.26返回字符串前有0x0、0x1，MYSQL 8.0.21版本没有这个问题
        // https://gitlab.yunshan.net/platform/trident/-/merge_requests/2592#note_401425
        String::from_utf8_lossy(&payload[2..]).into_owned()
    } else {
        String::from_utf8_lossy(payload).into_owned()
    }
}

impl MysqlLog {
    fn greeting(&mut self, payload: &[u8]) -> Result<()> {
        let mut remain = payload.len();
        if remain < PROTOCOL_VERSION_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        self.protocol_version = payload[PROTOCOL_VERSION_OFFSET];
        remain -= PROTOCOL_VERSION_LEN;
        let server_version_pos = payload[SERVER_VERSION_OFFSET..]
            .iter()
            .position(|&x| x == SERVER_VERSION_EOF)
            .unwrap_or_default();
        if server_version_pos <= 0 {
            return Err(Error::MysqlLogParseFailed);
        }
        remain -= server_version_pos as usize;
        if remain < THREAD_ID_LEN + 1 {
            return Err(Error::MysqlLogParseFailed);
        }
        Ok(())
    }

    fn request(
        &mut self,
        payload: &[u8],
        trace_id: Option<&str>,
        info: &mut MysqlInfo,
    ) -> Result<()> {
        if payload.len() < COMMAND_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        info.command = payload[COMMAND_OFFSET];
        match info.command {
            COM_QUIT | COM_FIELD_LIST | COM_STMT_CLOSE | COM_STMT_FETCH => (),
            COM_INIT_DB | COM_QUERY | COM_STMT_PREPARE => {
                info.request_string(&payload[COMMAND_OFFSET + COMMAND_LEN..], trace_id);
            }
            COM_STMT_EXECUTE => {
                info.statement_id(&payload[STATEMENT_ID_OFFSET..]);
            }
            COM_PING => {}
            _ => return Err(Error::MysqlLogParseFailed),
        }
        self.perf_stats.as_mut().map(|p| p.inc_req());
        Ok(())
    }

    fn decode_compress_int(payload: &[u8]) -> u64 {
        let remain = payload.len();
        if remain == 0 {
            return 0;
        }
        let value = payload[0];
        match value {
            INT_FLAGS_2 if remain > INT_BASE_LEN + 2 => {
                bytes::read_u16_le(&payload[INT_BASE_LEN..]) as u64
            }
            INT_FLAGS_3 if remain > INT_BASE_LEN + 3 => {
                bytes::read_u16_le(&payload[INT_BASE_LEN..]) as u64
                    | ((payload[INT_BASE_LEN + 2] as u64) << 16)
            }
            INT_FLAGS_8 if remain > INT_BASE_LEN + 8 => {
                bytes::read_u64_le(&payload[INT_BASE_LEN..])
            }
            _ => value as u64,
        }
    }

    fn set_status(&mut self, status_code: u16, info: &mut MysqlInfo) {
        if status_code != 0 {
            if status_code >= 2000 && status_code <= 2999 {
                info.status = L7ResponseStatus::ClientError;
            } else {
                info.status = L7ResponseStatus::ServerError;
            }
        } else {
            info.status = L7ResponseStatus::Ok;
        }
    }

    fn response(&mut self, payload: &[u8], info: &mut MysqlInfo) -> Result<()> {
        let mut remain = payload.len();
        if remain < RESPONSE_CODE_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        info.response_code = payload[RESPONSE_CODE_OFFSET];
        remain -= RESPONSE_CODE_LEN;
        match info.response_code {
            MYSQL_RESPONSE_CODE_ERR => {
                if remain > ERROR_CODE_LEN {
                    let code = bytes::read_u16_le(&payload[ERROR_CODE_OFFSET..]);
                    info.error_code = Some(code as i32);
                    self.set_status(code, info);
                    remain -= ERROR_CODE_LEN;
                }
                let error_message_offset =
                    if remain > SQL_STATE_LEN && payload[SQL_STATE_OFFSET] == SQL_STATE_MARKER {
                        SQL_STATE_OFFSET + SQL_STATE_LEN
                    } else {
                        SQL_STATE_OFFSET
                    };
                if error_message_offset < payload.len() {
                    info.error_message =
                        String::from_utf8_lossy(&payload[error_message_offset..]).into_owned();
                }
                self.perf_stats.as_mut().map(|p| p.inc_resp_err());
            }
            MYSQL_RESPONSE_CODE_OK => {
                info.status = L7ResponseStatus::Ok;
                info.affected_rows =
                    MysqlLog::decode_compress_int(&payload[AFFECTED_ROWS_OFFSET..]);
                info.statement_id(&payload[STATEMENT_ID_OFFSET..]);
            }
            _ => (),
        }
        self.perf_stats.as_mut().map(|p| p.inc_resp());
        Ok(())
    }

    fn check(payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }

        let mut header = MysqlHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return false;
        }
        let offset = offset as usize;

        if header.number != 0 || offset + header.length as usize > payload.len() {
            return false;
        }

        let protocol_version_or_query_type = payload[offset];
        match protocol_version_or_query_type {
            COM_QUERY | COM_STMT_PREPARE => {
                let context = mysql_string(&payload[offset + 1..]);
                return context.is_ascii() && is_mysql(&context);
            }
            _ => {}
        }
        false
    }

    // return is_greeting?
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        trace_id: Option<&str>,
        info: &mut MysqlInfo,
    ) -> Result<bool> {
        if proto != IpProtocol::TCP {
            return Err(Error::InvalidIpProtocol);
        }

        let mut header = MysqlHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return Err(Error::MysqlLogParseFailed);
        }
        let offset = offset as usize;
        let msg_type = header
            .check(direction, offset, payload)
            .ok_or(Error::MysqlLogParseFailed)?;

        match msg_type {
            LogMessageType::Request => self.request(&payload[offset..], trace_id, info)?,
            LogMessageType::Response => self.response(&payload[offset..], info)?,
            LogMessageType::Other => {
                self.greeting(&payload[offset..])?;
                return Ok(true);
            }
            _ => return Err(Error::MysqlLogParseFailed),
        };
        info.msg_type = msg_type;

        Ok(false)
    }
}

#[derive(Debug, Default)]
pub struct MysqlHeader {
    length: u32,
    number: u8,
}

impl MysqlHeader {
    pub fn decode(&mut self, payload: &[u8]) -> isize {
        if payload.len() < 5 {
            return -1;
        }
        let len = bytes::read_u32_le(payload) & 0xffffff;
        if payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_OK
            || payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_ERR
            || payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_EOF
            || payload[NUMBER_OFFSET] == 0
        {
            self.length = len;
            self.number = payload[NUMBER_OFFSET];
            return HEADER_LEN as isize;
        }
        let offset = len as usize + HEADER_LEN;
        if offset >= payload.len() {
            return 0;
        }
        let offset = offset as isize;
        offset + self.decode(&payload[offset as usize..])
    }

    pub fn check(
        &self,
        direction: PacketDirection,
        offset: usize,
        payload: &[u8],
    ) -> Option<LogMessageType> {
        if offset >= payload.len() || self.length == 0 {
            return None;
        }

        match direction {
            // greeting
            PacketDirection::ServerToClient if self.number == 0 => {
                let payload = &payload[offset..];
                if payload.len() < PROTOCOL_VERSION_LEN {
                    return None;
                }
                let protocol_version = payload[PROTOCOL_VERSION_OFFSET];
                let index = payload[SERVER_VERSION_OFFSET..]
                    .iter()
                    .position(|&x| x == SERVER_VERSION_EOF)?;
                if index != 0 && protocol_version == PROTOCOL_VERSION {
                    Some(LogMessageType::Other)
                } else {
                    None
                }
            }
            PacketDirection::ServerToClient => Some(LogMessageType::Response),
            PacketDirection::ClientToServer if self.number == 0 => Some(LogMessageType::Request),
            _ => None,
        }
    }
}

// extra trace id from comment like # TraceID: xxxxxxxxxxxxxxx
fn extra_sql_trace_id(sql: &str, trace_id: &str) -> Option<String> {
    for i in comment_parser::MysqlCommentParserIter::new(sql) {
        let s = i.trim();
        let Some(idx) = s.find(trace_id) else {
            continue;
        };

        let start = idx + trace_id.len() + 1;
        if start < s.len() {
            return Some((&s[start..].trim()).to_string());
        }
    }
    None
}

// test log parse
#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/mysql";

    fn run(name: &str) -> String {
        let pcap_file = Path::new(FILE_DIR).join(name);
        let capture = Capture::load_pcap(pcap_file, Some(1400));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut mysql = MysqlLog::default();
        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut previous_command = 0u8;
        for packet in packets.iter_mut() {
            packet.lookup_key.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };
            let is_mysql = mysql.check_payload(
                payload,
                &ParseParam::new(packet as &MetaPacket, log_cache.clone(), true, true),
            );

            let info = mysql.parse_payload(
                payload,
                &ParseParam::new(&*packet, log_cache.clone(), true, true),
            );

            if let Ok(info) = info {
                if info.is_none() {
                    let mut i = MysqlInfo::default();
                    i.protocol_version = mysql.protocol_version;
                    output.push_str(&format!("{:?} is_mysql: {}\r\n", i, is_mysql));
                    previous_command = 0;
                    continue;
                }
                match info.unwrap_single() {
                    L7ProtocolInfo::MysqlInfo(mut i) => {
                        if i.app_proto_head().unwrap().msg_type == LogMessageType::Request {
                            previous_command = i.command;
                        } else {
                            if previous_command != COM_QUERY {
                                i.affected_rows = 0;
                            }
                            previous_command = 0;
                        }

                        i.rrt = 0;
                        output.push_str(&format!("{:?} is_mysql: {}\r\n", i, is_mysql));
                    }
                    _ => unreachable!(),
                }
            } else {
                let mut i = MysqlInfo::default();
                i.protocol_version = mysql.protocol_version;
                output.push_str(&format!("{:?} is_mysql: {}\r\n", i, is_mysql));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("mysql-statement-id.pcap", "mysql-statement-id.result"),
            ("mysql-statement.pcap", "mysql-statement.result"),
            ("mysql.pcap", "mysql.result"),
            ("mysql-error.pcap", "mysql-error.result"),
            ("mysql-table-desc.pcap", "mysql-table-desc.result"),
            ("mysql-table-insert.pcap", "mysql-table-insert.result"),
            ("mysql-table-delete.pcap", "mysql-table-delete.result"),
            ("mysql-table-update.pcap", "mysql-table-update.result"),
            ("mysql-table-select.pcap", "mysql-table-select.result"),
            ("mysql-table-create.pcap", "mysql-table-create.result"),
            ("mysql-table-destroy.pcap", "mysql-table-destroy.result"),
            ("mysql-table-alter.pcap", "mysql-table-alter.result"),
            ("mysql-database.pcap", "mysql-database.result"),
        ];

        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "output different from expected {}, written to {:?}",
                    item.1,
                    output_path
                );
            }
        }
    }

    #[test]
    fn check_perf() {
        let expecteds = vec![
            (
                "mysql.pcap",
                L7PerfStats {
                    request_count: 6,
                    response_count: 7,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 5,
                    rrt_sum: 373,
                    rrt_max: 123,
                },
            ),
            (
                "mysql-error.pcap",
                L7PerfStats {
                    request_count: 4,
                    response_count: 4,
                    err_client_count: 0,
                    err_server_count: 1,
                    err_timeout: 0,
                    rrt_count: 3,
                    rrt_sum: 226,
                    rrt_max: 146,
                },
            ),
            (
                "171-mysql.pcap",
                L7PerfStats {
                    request_count: 390,
                    response_count: 390,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 390,
                    rrt_sum: 127090,
                    rrt_max: 5355,
                },
            ),
        ];

        for item in expecteds.iter() {
            assert_eq!(item.1, run_perf(item.0), "pcap {} check failed", item.0);
        }
    }

    fn run_perf(pcap: &str) -> L7PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
        let mut mysql = MysqlLog::default();

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), Some(1400));
        let mut packets = capture.as_meta_packets();

        let first_src_mac = packets[0].lookup_key.src_mac;
        for packet in packets.iter_mut() {
            if packet.lookup_key.src_mac == first_src_mac {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            if packet.get_l4_payload().is_some() {
                let param = &ParseParam::new(&*packet, rrt_cache.clone(), true, true);
                let _ = mysql.parse_payload(packet.get_l4_payload().unwrap(), param);
            }
        }
        mysql.perf_stats.unwrap()
    }
}
