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

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::mem::swap;
use std::{
    cmp::min,
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::Duration,
};

use arc_swap::access::Access;
use log::{info, warn};
use rand::prelude::{Rng, SeedableRng, SmallRng};

use super::{
    AppProtoHead, AppProtoLogsBaseInfo, AppProtoLogsData, BoxAppProtoLogsData, LogMessageType,
};

use crate::{
    common::{
        enums::EthernetType,
        flow::{get_uniq_flow_id_in_one_minute, PacketDirection, SignalSource},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        meta_packet::ProtocolData,
        MetaPacket, TaggedFlow,
    },
    config::handler::LogParserAccess,
    flow_generator::{Error::L7LogCanNotMerge, FLOW_METRICS_PEER_DST, FLOW_METRICS_PEER_SRC},
    metric::document::TapSide,
    rpc::get_timestamp,
    utils::stats::{Counter, CounterType, CounterValue, RefCountable},
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use public::utils::string::get_string_from_chars;
use public::{
    queue::{DebugSender, Error, Receiver},
    utils::net::MacAddr,
};

const QUEUE_BATCH_SIZE: usize = 1024;
const RCV_TIMEOUT: Duration = Duration::from_secs(1);
// 尽力而为的聚合默认120秒(AppProtoLogs.aggr*SLOT_WIDTH)内的请求和响应
pub const SLOT_WIDTH: u64 = 5; // 每个slot存5秒
const SLOT_CACHED_COUNT: u64 = 100000; // 每个slot平均缓存的FLOW数

const THROTTLE_BUCKET_BITS: u8 = 2;
const THROTTLE_BUCKET: usize = 1 << THROTTLE_BUCKET_BITS; // 2^N。由于发送方是有突发的，需要累积一定时间做采样

#[derive(Debug)]
pub struct MetaAppProto {
    base_info: AppProtoLogsBaseInfo,
    direction: PacketDirection,
    direction_score: u8,
    l7_info: L7ProtocolInfo,
}

impl MetaAppProto {
    pub fn new(
        flow: &TaggedFlow,
        meta_packet: &MetaPacket,
        l7_info: L7ProtocolInfo,
        head: AppProtoHead,
    ) -> Option<Self> {
        let mut base_info = AppProtoLogsBaseInfo {
            start_time: meta_packet.lookup_key.timestamp.into(),
            end_time: meta_packet.lookup_key.timestamp.into(),
            flow_id: flow.flow.flow_id,
            vtap_id: flow.flow.flow_key.vtap_id,
            tap_type: flow.flow.flow_key.tap_type,
            tap_port: flow.flow.flow_key.tap_port,
            signal_source: flow.flow.signal_source,
            tap_side: flow.flow.tap_side,
            head,
            protocol: meta_packet.lookup_key.proto,
            is_vip_interface_src: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC]
                .is_vip_interface,
            is_vip_interface_dst: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST]
                .is_vip_interface,
            gpid_0: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].gpid,
            gpid_1: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].gpid,
            mac_src: MacAddr::ZERO,
            mac_dst: MacAddr::ZERO,
            ip_src: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].nat_real_ip,
            ip_dst: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].nat_real_ip,
            is_ipv6: meta_packet.lookup_key.eth_type == EthernetType::IPV6,
            port_src: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].nat_real_port,
            port_dst: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].nat_real_port,
            l3_epc_id_src: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].l3_epc_id,
            l3_epc_id_dst: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].l3_epc_id,
            req_tcp_seq: 0,
            resp_tcp_seq: 0,
            process_id_0: 0,
            process_id_1: 0,
            process_kname_0: "".to_string(),
            process_kname_1: "".to_string(),
            syscall_trace_id_request: 0,
            syscall_trace_id_response: 0,
            syscall_trace_id_thread_0: 0,
            syscall_trace_id_thread_1: 0,
            syscall_coroutine_0: 0,
            syscall_coroutine_1: 0,
            syscall_cap_seq_0: 0,
            syscall_cap_seq_1: 0,
            ebpf_type: meta_packet.ebpf_type,
            netns_id_0: 0,
            netns_id_1: 0,
        };

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if meta_packet.signal_source == SignalSource::EBPF {
            let is_src = meta_packet.lookup_key.l2_end_0;
            let process_name = get_string_from_chars(&meta_packet.process_kname);
            if is_src {
                base_info.process_id_0 = meta_packet.process_id;
                base_info.process_kname_0 = process_name;
                base_info.netns_id_0 = meta_packet.netns_id;
                base_info.syscall_coroutine_0 = meta_packet.coroutine_id;
            } else {
                base_info.process_id_1 = meta_packet.process_id;
                base_info.process_kname_1 = process_name;
                base_info.netns_id_1 = meta_packet.netns_id;
                base_info.syscall_coroutine_1 = meta_packet.coroutine_id;
            }
        }

        if flow.flow.tap_side == TapSide::Local {
            base_info.mac_src = flow.flow.flow_key.mac_src;
            base_info.mac_dst = flow.flow.flow_key.mac_dst;
        } else {
            if base_info.is_vip_interface_src {
                base_info.mac_src = flow.flow.flow_key.mac_src;
            }
            if base_info.is_vip_interface_dst {
                base_info.mac_dst = flow.flow.flow_key.mac_dst;
            }
        }

        let seq = if let ProtocolData::TcpHeader(tcp_data) = &meta_packet.protocol_data {
            tcp_data.seq
        } else {
            0
        };
        if meta_packet.lookup_key.direction == PacketDirection::ClientToServer {
            base_info.req_tcp_seq = seq + l7_info.tcp_seq_offset();

            // ebpf info
            base_info.syscall_trace_id_request = meta_packet.syscall_trace_id;
            base_info.syscall_trace_id_thread_0 = meta_packet.thread_id;
            base_info.syscall_cap_seq_0 = meta_packet.cap_seq;
        } else {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if meta_packet.signal_source == SignalSource::EBPF {
                swap(&mut base_info.process_id_0, &mut base_info.process_id_1);
                swap(
                    &mut base_info.process_kname_0,
                    &mut base_info.process_kname_1,
                );
            }

            base_info.resp_tcp_seq = seq + l7_info.tcp_seq_offset();

            // ebpf info
            base_info.syscall_trace_id_response = meta_packet.syscall_trace_id;
            base_info.syscall_trace_id_thread_1 = meta_packet.thread_id;
            base_info.syscall_cap_seq_1 = meta_packet.cap_seq;
        }

        Some(Self {
            base_info,
            direction: meta_packet.lookup_key.direction,
            direction_score: flow.flow.direction_score,
            l7_info,
        })
    }
}

#[derive(Default)]
pub struct SessionAggrCounter {
    send_before_window: AtomicU64,
    receive: AtomicU64,
    merge: AtomicU64,
    cached: AtomicU64,
    throttle_drop: AtomicU64,
}

// FIXME: counter not registered
impl RefCountable for SessionAggrCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "send-before-window",
                CounterType::Counted,
                CounterValue::Unsigned(self.send_before_window.swap(0, Ordering::Relaxed)),
            ),
            (
                "receive",
                CounterType::Counted,
                CounterValue::Unsigned(self.receive.swap(0, Ordering::Relaxed)),
            ),
            (
                "merge",
                CounterType::Counted,
                CounterValue::Unsigned(self.merge.swap(0, Ordering::Relaxed)),
            ),
            (
                "cached",
                CounterType::Counted,
                CounterValue::Unsigned(self.cached.load(Ordering::Relaxed)),
            ),
            (
                "throttle-drop",
                CounterType::Counted,
                CounterValue::Unsigned(self.throttle_drop.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

struct Throttle {
    interval: Duration,
    last_flush_time: Duration,
    throttle: u32,
    throttle_multiple: u32,
    period_count: u32,
    config: LogParserAccess,
    small_rng: SmallRng,
}

impl Throttle {
    fn new(config: LogParserAccess, interval: u64) -> Self {
        Self {
            config,
            interval: Duration::from_secs(interval),
            throttle: 0,
            throttle_multiple: interval as u32,
            period_count: 0,
            last_flush_time: Duration::ZERO,
            small_rng: SmallRng::from_entropy(),
        }
    }

    fn tick(&mut self, current: Duration) {
        self.last_flush_time = current;
        self.period_count = 0;
        self.throttle =
            (self.config.load().l7_log_collect_nps_threshold as u32) * self.throttle_multiple;
    }

    fn acquire(&mut self, current: Duration) -> bool {
        self.period_count += 1;

        // Local timestamp may be modified
        if current < self.last_flush_time {
            self.last_flush_time = current;
        }

        if current > self.last_flush_time + self.interval || self.last_flush_time.is_zero() {
            self.tick(current);
        }

        if self.period_count >= self.throttle {
            return self.small_rng.gen_range(0..self.period_count) < self.throttle;
        }

        true
    }
}

struct SessionQueue {
    aggregate_start_time: Duration,
    last_flush_time: Duration,

    window_size: usize,
    time_window: Option<Vec<HashMap<u64, Box<AppProtoLogsData>>>>,

    throttle: Throttle,

    counter: Arc<SessionAggrCounter>,
    output_queue: DebugSender<BoxAppProtoLogsData>,
    config: LogParserAccess,
    ntp_diff: Arc<AtomicI64>,
}

impl SessionQueue {
    fn new(
        counter: Arc<SessionAggrCounter>,
        output_queue: DebugSender<BoxAppProtoLogsData>,
        config: LogParserAccess,
        ntp_diff: Arc<AtomicI64>,
    ) -> Self {
        //l7_log_session_timeout 20s-300s ，window_size = 4-60，所以 SessionQueue.time_window 预分配内存
        let window_size =
            (config.load().l7_log_session_aggr_timeout.as_secs() / SLOT_WIDTH) as usize;
        let time_window = vec![HashMap::new(); window_size];
        let throttle = Throttle::new(config.clone(), SLOT_WIDTH);
        Self {
            aggregate_start_time: Duration::ZERO,
            last_flush_time: Duration::ZERO,
            time_window: Some(time_window),
            config,
            ntp_diff,
            window_size,

            throttle,

            counter,
            output_queue,
        }
    }

    fn flush_one_slot(&mut self) {
        let now = get_timestamp(self.ntp_diff.load(Ordering::Relaxed));
        // If the local timestamp adjustment requires recalculating the interval
        if now < self.last_flush_time {
            self.last_flush_time = now - Duration::from_secs(1);
        }
        // 每秒检测是否flush, 若超过2倍slot时间未收到数据，则发送1个slot的数据
        let interval = now.saturating_sub(self.last_flush_time);
        // mean subtracting overflow, but `self.last_flush_time` only assign by `now` local variable, so
        // it mean get get time error
        if interval.is_zero() {
            warn!("SystemTime::now call error check host associated time syscall");
            return;
        }
        if interval.as_secs() < 2 * SLOT_WIDTH {
            return;
        }
        let mut time_window = match self.time_window.take() {
            Some(t) => t,
            None => return,
        };
        self.last_flush_time = now;
        // flush 1个slot的数据
        self.flush_window(1, &mut time_window);
        self.time_window.replace(time_window);
    }

    // 按时间窗口(6*10秒)聚合HTTP,DNS的请求和响应流程:
    //   - 收到请求，根据报文时间找到对应的时间窗口的缓存数据(若小于时间窗口的最小时间，则直接发送，若大于时间窗口的最大时间，则依次移动窗口，直到时间处于窗口内)
    //      - 若已缓存了(HTTPV1.1或重传时，存在一条流连续发送多个请求，且无法通过StreamID区分，则缓存最后一次的请求), 则发送旧的请求，存储当前请求
    //      - 若未缓存，则判断是否达到最大缓存数量
    //        - 未达到，则缓存
    //        - 达到， 则直接发送
    //   - 收到响应，根据报文时间-RRT时间，找到对应的时间窗口，查找是否有匹配的请求
    //      - 若有， 则合并请求和响应(将响应的数据填入请求中，并修改请求的类型为会话)，释放当前响应，发送会话
    //      - 若没有, 则直接发送当前响应
    fn aggregate_session_and_send(&mut self, item: Box<AppProtoLogsData>) {
        self.counter.receive.fetch_add(1, Ordering::Relaxed);

        let slot_time = if item.base_info.head.msg_type == LogMessageType::Response {
            // request = response - RRT
            (item.base_info.start_time - Duration::from_micros(item.base_info.head.rrt)).as_secs()
        } else {
            // if req and rrt not 0, maybe ebpf disorder, the slot time is resp time and req should add the rrt.
            (item.base_info.start_time + Duration::from_micros(item.base_info.head.rrt)).as_secs()
        };
        if slot_time < self.aggregate_start_time.as_secs() {
            if self
                .counter
                .send_before_window
                .fetch_add(1, Ordering::Relaxed)
                == 0
            {
                info!("l7 log {:?} (slot timestamp {:?}, start time: {:?}, rrt: {:?}) out of session aggregate window({:?}), will be sent without merge.",
                    item.base_info.head.proto,
                    Duration::from_secs(slot_time),
                    item.base_info.start_time,
                    Duration::from_micros(item.base_info.head.rrt),
                    self.aggregate_start_time
                );
            }
            self.send(item);
            return;
        }

        let mut slot = ((slot_time - self.aggregate_start_time.as_secs()) / SLOT_WIDTH) as usize;
        let mut time_window = match self.time_window.take() {
            Some(t) => t,
            None => return,
        };
        // 使time window维持在固定的长度
        if slot >= self.window_size {
            // flush过期的几个slot的数据
            self.flush_window(slot - self.window_size + 1, &mut time_window);
            slot = self.window_size - 1;
        }

        // 因为数组提前分配hashmap, slot < self.window_size 所以必然存在
        let map = time_window.get_mut(slot).unwrap();
        let key = if item.base_info.signal_source == SignalSource::EBPF {
            // if the l7 log from ebpf, use AppProtoLogsData::ebpf_flow_session_id()
            item.ebpf_flow_session_id()
        } else {
            Self::calc_key(&item)
        };
        match item.base_info.head.msg_type {
            LogMessageType::Request => {
                self.on_request_log(map, item, key);
            }
            LogMessageType::Response => {
                self.on_response_log(map, item, key);
            }
            LogMessageType::Session => self.send(item),
            _ => (),
        }

        self.time_window.replace(time_window);
    }

    fn on_request_log(
        &mut self,
        map: &mut HashMap<u64, Box<AppProtoLogsData>>,
        mut item: Box<AppProtoLogsData>,
        key: u64,
    ) {
        if let Some(mut p) = map.remove(&key) {
            if item.need_protocol_merge() {
                let _ = p.session_merge(*item);
                if p.special_info.is_session_end() {
                    self.counter.cached.fetch_sub(1, Ordering::Relaxed);
                    self.send(p);
                } else {
                    map.insert(key, p);
                }
            } else {
                // 若乱序，已存在响应，则可以匹配为会话，则聚合响应发送
                // If the order is out of order and there is a response, it can be matched as a session, and the aggregated response is sent
                if p.is_response() && p.base_info.start_time > item.base_info.start_time {
                    // if can not merge, send req and resp directly.
                    if let Err(L7LogCanNotMerge(p)) = item.session_merge(*p) {
                        self.send(Box::new(p));
                    }
                    self.counter.cached.fetch_sub(1, Ordering::Relaxed);
                    self.counter.merge.fetch_add(1, Ordering::Relaxed);
                    self.send(item);
                } else {
                    // If p is req or resp time lt req time, p is not item corresponding response, send the earlier log and save the later log
                    if p.base_info.start_time > item.base_info.start_time {
                        self.send(item);
                        map.insert(key, p);
                    } else {
                        self.send(p);
                        map.insert(key, item);
                    }
                }
            }
        } else {
            if item.need_protocol_merge() {
                let (req_end, resp_end) = item.special_info.is_req_resp_end();
                // http2 uprobe may receive resp_end repeatedly, ignore it directly to prevent accumulation
                if req_end || resp_end {
                    return;
                }
            }

            if self.counter.cached.load(Ordering::Relaxed)
                >= self.window_size as u64 * SLOT_CACHED_COUNT
            {
                self.send(item); // Prevent too many logs from being cached
            } else {
                map.insert(key, item);
                self.counter.cached.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn on_response_log(
        &mut self,
        map: &mut HashMap<u64, Box<AppProtoLogsData>>,
        item: Box<AppProtoLogsData>,
        key: u64,
    ) {
        // response, 需要找到request并merge
        if let Some(mut p) = map.remove(&key) {
            if item.need_protocol_merge() {
                let _ = p.session_merge(*item);

                if p.special_info.is_session_end() {
                    self.counter.cached.fetch_sub(1, Ordering::Relaxed);
                    self.send(p);
                } else {
                    map.insert(key, p);
                }
            } else {
                if p.is_request() && item.base_info.start_time > p.base_info.start_time {
                    // if can not merge, send req and resp directly.
                    if let Err(L7LogCanNotMerge(item)) = p.session_merge(*item) {
                        self.send(Box::new(item));
                    }
                    self.counter.cached.fetch_sub(1, Ordering::Relaxed);
                    self.counter.merge.fetch_add(1, Ordering::Relaxed);
                    self.send(p);
                } else {
                    // If p is resp or resp time lt req time, p is not the item corresponding req, send the earlier log and save the later log
                    if p.base_info.start_time < item.base_info.start_time {
                        self.send(p);
                        map.insert(key, item);
                    } else {
                        self.send(item);
                        map.insert(key, p);
                    }
                }
            }
        } else {
            if item.need_protocol_merge() {
                let (req_end, resp_end) = item.special_info.is_req_resp_end();
                // http2 uprobe 有可能会重复收到resp_end, 直接忽略，防止堆积
                // http2 uprobe may receive resp_end repeatedly, ignore it directly to prevent accumulation
                if req_end || resp_end {
                    return;
                }
            }

            if self.counter.cached.load(Ordering::Relaxed)
                >= self.window_size as u64 * SLOT_CACHED_COUNT
            {
                self.send(item); // Prevent too many logs from being cached
            } else {
                map.insert(key, item);
                self.counter.cached.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn clear(&mut self) {
        let mut time_window = match self.time_window.take() {
            Some(t) => t,
            None => return,
        };
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        'outer: for map in time_window.drain(..) {
            self.counter
                .cached
                .fetch_sub(map.len() as u64, Ordering::Relaxed);
            for item in map.into_values() {
                if batch.len() >= QUEUE_BATCH_SIZE {
                    if let Err(Error::Terminated(..)) = self.output_queue.send_all(&mut batch) {
                        warn!("output queue terminated");
                        batch.clear();
                        break 'outer;
                    }
                }
                batch.push(BoxAppProtoLogsData(item));
            }
        }
        if !batch.is_empty() {
            if let Err(Error::Terminated(..)) = self.output_queue.send_all(&mut batch) {
                warn!("output queue terminated");
            }
        }
        self.time_window.replace(time_window);
    }

    fn calc_key(item: &AppProtoLogsData) -> u64 {
        if let L7ProtocolInfo::MqttInfo(_) = item.special_info {
            return item.base_info.flow_id;
        }
        let request_id = if let Some(id) = item.special_info.session_id() {
            id
        } else {
            0
        };
        // key需保证流日志1分钟内唯一，由1分钟内唯一的flow_id和request_id组成
        get_uniq_flow_id_in_one_minute(item.base_info.flow_id) << 32 | (request_id as u64)
    }

    fn flush_window(
        &mut self,
        n: usize,
        time_window: &mut Vec<HashMap<u64, Box<AppProtoLogsData>>>,
    ) {
        let delete_num = min(n, self.window_size);
        for i in 0..delete_num {
            let map = time_window.get_mut(i).unwrap();
            self.counter
                .cached
                .fetch_sub(map.len() as u64, Ordering::Relaxed);
            self.send_all(map.drain().map(|(_, item)| item).collect());
            map.shrink_to_fit();
        }
        let mut maps = time_window.drain(0..delete_num).collect();
        time_window.append(&mut maps);

        // update timestamp
        self.aggregate_start_time =
            Duration::from_secs(self.aggregate_start_time.as_secs() + n as u64 * SLOT_WIDTH);
    }

    fn send(&mut self, item: Box<AppProtoLogsData>) {
        if item.special_info.skip_send() {
            return;
        }

        if !self.throttle.acquire(item.base_info.start_time) {
            self.counter.throttle_drop.fetch_add(1, Ordering::Relaxed);
            return;
        }

        if let Err(Error::Terminated(..)) = self.output_queue.send(BoxAppProtoLogsData(item)) {
            warn!("output queue terminated");
        }
    }

    fn send_all(&mut self, items: Vec<Box<AppProtoLogsData>>) {
        for item in items {
            self.send(item);
        }
    }
}

pub struct SessionAggregator {
    input_queue: Arc<Receiver<Box<MetaAppProto>>>,
    output_queue: DebugSender<BoxAppProtoLogsData>,
    id: u32,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    counter: Arc<SessionAggrCounter>,
    config: LogParserAccess,
    ntp_diff: Arc<AtomicI64>,
}

impl SessionAggregator {
    pub fn new(
        input_queue: Receiver<Box<MetaAppProto>>,
        output_queue: DebugSender<BoxAppProtoLogsData>,
        id: u32,
        config: LogParserAccess,
        ntp_diff: Arc<AtomicI64>,
    ) -> (Self, Arc<SessionAggrCounter>) {
        let counter: Arc<SessionAggrCounter> = Default::default();
        (
            Self {
                input_queue: Arc::new(input_queue),
                output_queue,
                id,
                running: Default::default(),
                thread: Mutex::new(None),
                counter: counter.clone(),
                config,
                ntp_diff,
            },
            counter,
        )
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let running = self.running.clone();
        let counter = self.counter.clone();
        let input_queue = self.input_queue.clone();
        let output_queue = self.output_queue.clone();

        let config = self.config.clone();
        let ntp_diff = self.ntp_diff.clone();

        let thread = thread::Builder::new()
            .name("protocol-logs-parser".to_owned())
            .spawn(move || {
                let mut session_queue =
                    SessionQueue::new(counter, output_queue, config.clone(), ntp_diff);

                let mut batch_buffer = Vec::with_capacity(QUEUE_BATCH_SIZE);

                while running.load(Ordering::Relaxed) {
                    match input_queue.recv_all(&mut batch_buffer, Some(RCV_TIMEOUT)) {
                        Ok(_) => {
                            let config = config.load();
                            for app_proto in batch_buffer.drain(..) {
                                if config.l7_log_ignore_tap_sides
                                    [app_proto.base_info.tap_side as usize]
                                {
                                    continue;
                                }
                                session_queue.aggregate_session_and_send(Box::new(
                                    AppProtoLogsData {
                                        base_info: (*app_proto).base_info.clone(),
                                        special_info: (*app_proto).l7_info,
                                        direction_score: (*app_proto).direction_score,
                                    },
                                ));
                            }
                        }
                        Err(Error::Timeout) => {
                            session_queue.flush_one_slot();
                            continue;
                        }
                        Err(Error::Terminated(..)) => break,
                        Err(Error::BatchTooLarge(_)) => unreachable!(),
                    };
                }
                session_queue.clear();
            })
            .unwrap();
        self.thread.lock().unwrap().replace(thread);
        info!("app protocol logs parser (id={}) started", self.id);
    }

    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return None;
        }
        info!("notified app protocol logs parser (id={}) to stop", self.id);
        self.thread.lock().unwrap().take()
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
        info!("app protocol logs parser (id={}) stopped", self.id);
    }
}
