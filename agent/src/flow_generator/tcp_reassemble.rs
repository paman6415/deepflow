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

use log::error;
use public::ringbuf::RingBuf;
use std::mem::swap;

const DIRECTION_C2S: u8 = 0;
const DIRECTION_S2C: u8 = 1;

#[derive(Debug)]
pub enum TcpReassembleError {
    // the frame seq is before the base seq
    FrameBeforeBase,
    // frame exist
    FrameExist,
    // tcp seq and payload not correspond or buffer not enough to place the frame
    BufferFlush(Vec<(Vec<u8>, Vec<TcpFragementMeta>)>),
}

enum FramePositionResult {
    BeforeBase,
    Before(usize), // the frame is before idx
    After(usize),  // the frame is after idx
    Buffered,      // the frame is buffered, should ignore
    BadFrame(String),
}

pub type TcpReassembleResult = Result<(), TcpReassembleError>;

// newer frame is front
fn is_seq_loopback(s1: u32, s2: u32) -> bool {
    const HALF_TCP_SEQ_RANGE: u32 = 2147483648;
    s1.abs_diff(s2) > HALF_TCP_SEQ_RANGE
}

fn is_seq_before(before: u32, after: u32) -> bool {
    let lb = is_seq_loopback(before, after);
    (before <= after && !lb) || (before >= after && lb)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFragementMeta {
    pub seq: u32,
    pub payload_len: usize,
}

impl TcpFragementMeta {
    // whether the next frame is consequent
    fn is_next_consequent(&self, next: &Self) -> bool {
        self.next_seq() == next.seq
    }

    fn next_seq(&self) -> u32 {
        self.seq + (self.payload_len as u32)
    }
}

pub struct BufferData {
    // buffer with packet_size length, prealloc, len = l7_log_packet_size
    pub(super) buf: RingBuf<u8>,
    // len = max_tcp_reassemble_frag
    pub(super) tcp_meta: Vec<TcpFragementMeta>,
    pub(super) base_seq: Option<u32>,
    pub(super) max_frame: usize,
}

impl BufferData {
    fn frame_offset(&self, t: &TcpFragementMeta) -> usize {
        (t.seq - self.base_seq.unwrap()) as usize
    }

    fn is_empty(&self) -> bool {
        self.tcp_meta.is_empty()
    }

    fn buf_size(&self) -> usize {
        self.buf.cap()
    }

    // whether the frame is before base
    fn before_base(&self, f: &TcpFragementMeta) -> bool {
        self.base_seq
            .map(|base_seq| is_seq_before(f.seq, base_seq))
            .unwrap_or(false)
    }

    // get the consequent data, return tcp_meta_idx
    pub(super) fn get_consequent_idx(&self) -> Option<usize> {
        let mut f = None;
        if self.tcp_meta.is_empty() {
            None
        } else if self.tcp_meta.len() == 1 {
            Some(0)
        } else {
            self.tcp_meta
                .iter()
                .zip(self.tcp_meta.iter().skip(1))
                .position(|(a, b)| {
                    if a.is_next_consequent(b) {
                        false
                    } else {
                        f = Some(a);
                        true
                    }
                })
                .and_then(|i| Some(i))
                .or(Some(self.tcp_meta.len() - 1))
        }
    }

    // discard first n frame
    // must assure invoke tcp_reassemble() at lease once that base_seq is not None
    fn drain_frame_n(&mut self, n: usize) -> usize {
        if n == 0 || n > self.tcp_meta.len() {
            panic!("drain tcp frame is 0 or tcp frame out of index");
        }
        self.tcp_meta = self.tcp_meta.split_off(n - 1);
        let f = self.tcp_meta.remove(0);
        let off = self.frame_offset(&f) + f.payload_len;
        self.base_seq = self.base_seq.map(|s| s + off as u32);

        self.buf.drain_n(off);
        off
    }

    // pop first n frame
    // must assure invoke tcp_reassemble() at lease once that base_seq is not None
    // return (payload, tcp_meta)
    fn pop_frame_n(&mut self, n: usize) -> (Vec<u8>, Vec<TcpFragementMeta>) {
        if n == 0 || n > self.tcp_meta.len() {
            panic!("drain tcp frame is 0 or tcp frame out of index");
        }

        let mut p = self.tcp_meta.split_off(n);
        swap(&mut p, &mut self.tcp_meta);

        let latest = p.last().unwrap();
        let start = self.frame_offset(p.first().unwrap());
        let off = self.frame_offset(latest) + latest.payload_len - start;

        self.base_seq = self.base_seq.map(|seq| seq + off as u32 + start as u32);
        self.buf.pop_n(start);
        let payload = self.buf.pop_n(off);
        (payload, p.to_vec())
    }

    pub(super) fn pop_consequent_seq_data(&mut self) -> (Vec<u8>, Vec<TcpFragementMeta>) {
        let Some(meta_idx) = self.get_consequent_idx() else {
             return (vec![],vec![]);
         };
        self.pop_frame_n(meta_idx + 1)
    }

    /*
        drain the ringbuf and tcp meta data first consequent tcp seq data.
        must assure invoke tcp_reassemble() at lease once that base_seq is not None.
        return drain size
    */
    pub(super) fn drain_consequent_seq_data(&mut self) -> usize {
        let Some(meta_idx) = self.get_consequent_idx() else {
             return 0;
         };

        self.drain_frame_n(meta_idx + 1)
    }

    // get the waitting bytes between base seq and_first frame, return None if no tcp frame
    pub(super) fn get_waitting_buf_len_before_first_frame(&self) -> Option<usize> {
        if self.tcp_meta.len() == 0 {
            None
        } else {
            Some(self.frame_offset(self.tcp_meta.get(0).unwrap()))
        }
    }

    pub(super) fn drain_waitting_buf_len_before_first_frame(&mut self) -> usize {
        if self.tcp_meta.len() == 0 {
            return 0;
        }
        let f = self.tcp_meta.get(0).unwrap();
        let b = self.frame_offset(f);
        self.buf.drain_n(b);
        self.base_seq = Some(f.seq);
        b
    }

    // must assure the base seq is correct and frame is insert in correct pos and payload + preserve can not exceed
    fn insert_frame(&mut self, pos: usize, f: TcpFragementMeta, payload: &[u8]) {
        self.tcp_meta.insert(pos, f);
        let off = self.frame_offset(&f);
        if off > self.buf.len() {
            // perserve the buffer
            self.buf.perserve_n(off - self.buf.len());
        }
        self.buf.extend_from_offset(off, payload.iter().map(|b| *b))
    }

    /*
        if have no waitting before first frame, pop the first consequent seq data and pop the all rest consequent_seq_data,
        else pop all consequent seq data
    */
    fn flush_all_buf(&mut self) -> Vec<(Vec<u8>, Vec<TcpFragementMeta>)> {
        self.drain_consequent_seq_data();
        let mut v = vec![];

        loop {
            let (payload, meta) = self.pop_consequent_seq_data();
            let len = payload.len();
            if len == 0 {
                break;
            }
            v.push((payload, meta));
        }
        v
    }

    fn get_frame_position(&self, f: &TcpFragementMeta) -> FramePositionResult {
        assert_eq!(self.is_empty(), false);

        if self.before_base(f) {
            return FramePositionResult::BeforeBase;
        }

        let latest = self.tcp_meta.last().unwrap();
        // if frame after the latest
        if is_seq_before(latest.seq, f.seq) {
            if is_seq_before(latest.next_seq(), f.seq) {
                return FramePositionResult::After(self.tcp_meta.len() - 1);
            } else {
                return FramePositionResult::BadFrame(format!("the frame with seq: {}, payload_len: {}  after frame with seq:{}, payload_len: {} not conform tcp protocol",f.seq,f.payload_len,latest.seq,latest.payload_len));
            }
        }

        let (base_seq, latest_seq) = (self.base_seq.unwrap(), self.tcp_meta.last().unwrap().seq);
        // if the tcp seq is all increase, can use binary search
        let idx = if latest_seq >= base_seq {
            let (mut start, mut end) = (0, self.tcp_meta.len() - 1);
            while end > start {
                let mid = (end + start) / 2;
                if f.seq > self.tcp_meta.get(mid).unwrap().seq {
                    start = mid + 1
                } else {
                    end = mid
                }
            }
            end
        } else {
            let mut previous_seq = base_seq;
            let mut idx = None;
            for (i, t) in self.tcp_meta.iter().enumerate() {
                /*

                    use the difference value can regardless whether loopback

                    previous seq                                   t seq
                        |----------------(f seq?)-------------------|--------------(f seq?)---------|
                */
                if t.seq == f.seq {
                    return FramePositionResult::Buffered;
                }
                if (t.seq - previous_seq) > (f.seq - previous_seq) {
                    // frame is between previous and t
                    idx = Some(i);
                    break;
                }
                previous_seq = t.seq;
            }

            // the frame seq is between base and latest
            idx.unwrap()
        };

        let m = self.tcp_meta.get(idx).unwrap();
        if m.seq == f.seq {
            // for simpify, ignore the payload length
            return FramePositionResult::Buffered;
        }

        let previous = if idx == 0 {
            TcpFragementMeta {
                seq: base_seq,
                payload_len: 0,
            }
        } else {
            *self.tcp_meta.get(idx - 1).unwrap()
        };

        // frame is between previous and m
        if is_seq_before(previous.next_seq(), f.seq) && is_seq_before(f.next_seq(), m.seq) {
            return FramePositionResult::Before(idx);
        }
        FramePositionResult::BadFrame(format!("the frame with seq: {}, payload_len: {}  between frame with seq:{}, payload_len: {}  and frame with seq:{}, payload_len: {} not conform tcp protocol",
             f.seq,f.payload_len,
             previous.seq,
             previous.payload_len,
             m.seq,
             m.payload_len))
    }

    /*
        case -1: seq not conform the tcp protocol(for example payload length and tcp seq not correspond):
            flush all the frame and drop current frame.

        case 0: new frame or buffer empty:
            case 0.1: paylaod size >= buffer size, set the base_seq = paylaod size + seq ,not cache the frame
            case 0.2: paylaod size < buffer, set the base_seq = seq, cache the frame

        case 1: frame before the base_seq, regardless the payload size:
            return error directly

        case 2: frame can place to buffer:
            place to buffer
            case 2.1: if tcp frame is exceed (after place current frame):
                pop the first consequent data



        case 3: not enough buffer to place the frmae
            according to tcp protocol, if not enough buffer to place the frmae, this frame must after the latest frame in the buffer (because
            in tcp prorocol, the difference value of tcp seq is the tcp stream size between two frame). more exaclly, the frame seq must conform
            that: seq >= latest frame seq + latest frame payload length (in non lookback case)

            first, try to drain the waitting buffer before first frame:
                | preserve buffer| first frame | ... | latest frame | ...(not enough buffer to place frmae) |

                after drain the buffer:

                | first frame | ... | latest frame | free space |

                if the free space still not enough to place the frame, drop the consequent data and drain the waitting buffer before first frame
                until have enough buffer to place the frame

                | consequent data 1| preserve buffer | consequent data 2| ... | latest frame | free space |

                | preserve buffer | consequent data 2| ... | latest frame |          free space           |

                | consequent data 2| ... | latest frame |                   free space                    |

                ...

            if all frame pop and current payload < buffer size:
                is same to case 0.2

            if all frame pop and payload >= buffer size
                case 3.1: the frame is the next frame of latest frmae:
                    concat current frame to latest and prune to packet size
                case 3.2: not the next frame of latest frame:
                    pop the current frame Individually
    */
    pub(super) fn reassemble(
        &mut self,
        seq: u32,
        payload: &[u8], // payload must not prune in the param
    ) -> TcpReassembleResult {
        let frame = TcpFragementMeta {
            seq,
            payload_len: payload.len(),
        };

        // frame before than base frame, ignore. (case 1)
        if self.before_base(&frame) {
            return Err(TcpReassembleError::FrameBeforeBase);
        }

        // case 0: buf empty, is the first frame in this direction, set the frame as first frame
        if self.is_empty() {
            if payload.len() >= self.buf_size() {
                // case 0.1
                // it not return the frame because buf empty indicate the frame had parsed
                self.base_seq = Some(frame.next_seq());
            } else {
                // case 0.2
                self.base_seq = Some(frame.seq);
                self.insert_frame(0, frame, payload);
            }
            return Ok(());
        }

        match self.get_frame_position(&frame) {
            // before idx imply the buffer have enough space to place the frame
            FramePositionResult::Before(idx) => {
                // case 2
                self.insert_frame(idx, frame, payload);
                if self.tcp_meta.len() > self.max_frame {
                    // case 2.1
                    return Err(TcpReassembleError::BufferFlush(vec![
                        self.pop_consequent_seq_data()
                    ]));
                }
                Ok(())
            }
            FramePositionResult::After(idx) => {
                // if not after the latest, imply the buffer have enough space to place the frame
                // if after latest, maybe not enough buffer space to place the frmae
                if idx != self.tcp_meta.len() - 1
                    || self.frame_offset(&frame) + frame.payload_len <= self.buf_size()
                {
                    // case 2
                    self.insert_frame(idx + 1, frame, payload);
                    if self.tcp_meta.len() > self.max_frame {
                        // case 2.1
                        return Err(TcpReassembleError::BufferFlush(vec![
                            self.pop_consequent_seq_data()
                        ]));
                    }
                    return Ok(());
                }

                // not enough buffer space to place the frame
                // case 3
                let is_latest_next = self.tcp_meta.last().unwrap().is_next_consequent(&frame);
                let mut p = vec![];
                while self.frame_offset(&frame) + frame.payload_len > self.buf_size()
                    && !self.tcp_meta.is_empty()
                {
                    if self.get_waitting_buf_len_before_first_frame().unwrap() != 0 {
                        self.drain_waitting_buf_len_before_first_frame();
                        continue;
                    }
                    p.push(self.pop_consequent_seq_data());
                }

                if self.frame_offset(&frame) + frame.payload_len <= self.buf_size() {
                    self.insert_frame(self.tcp_meta.len(), frame, payload);
                    return Err(TcpReassembleError::BufferFlush(p));
                }

                //  same as case 0.2
                if self.is_empty() && payload.len() < self.buf_size() {
                    self.base_seq = Some(frame.seq);
                    self.insert_frame(0, frame, payload);
                    return Err(TcpReassembleError::BufferFlush(p));
                }

                // all buffer pop, but still can not place the frame
                if is_latest_next {
                    // case 3.1
                    let latest = p.last_mut().unwrap();
                    let latest_payload = &mut latest.0;
                    let latest_frames = &mut latest.1;
                    latest_payload.extend(&payload[..(self.buf_size() - latest_payload.len())]);
                    latest_frames.push(frame);
                } else {
                    // case 3.2
                    p.push(((&payload[..self.buf_size()]).to_vec(), vec![frame]));
                }
                let _ = self.base_seq.insert(frame.seq + frame.payload_len as u32);
                Err(TcpReassembleError::BufferFlush(p))
            }
            FramePositionResult::Buffered => Err(TcpReassembleError::FrameExist),
            FramePositionResult::BadFrame(s) => {
                error!("{}", s);
                Err(TcpReassembleError::BufferFlush(self.flush_all_buf()))
            }
            _ => unreachable!(),
        }
    }
}

pub struct TcpFlowReassembleBuf {
    buf_0: BufferData,
    // for serial protocol, only need single buffer, buf_1 and meta_1 will clean and keep empty after check_payload() success
    buf_1: BufferData,

    current_direction: Option<u8>,

    is_serial_protocol: bool,
}

impl TcpFlowReassembleBuf {
    pub fn new(buf_size: usize, max_frame: usize) -> Self {
        Self {
            buf_0: BufferData {
                buf: RingBuf::new(buf_size),
                tcp_meta: Vec::with_capacity(max_frame),
                base_seq: None,
                max_frame,
            },
            buf_1: BufferData {
                buf: RingBuf::new(buf_size),
                tcp_meta: Vec::with_capacity(max_frame),
                base_seq: None,
                max_frame,
            },
            current_direction: None,
            is_serial_protocol: true,
        }
    }

    /*
        some serial protocol not need the two side buffer when data from af_packet.
        the follow protocol will set to serial proto:
            HTTP1
            Redis

        due to ebpf will disorder, it must use two side buffer in any protocol.
    */
    pub fn set_to_serial_proto(&mut self) {
        if self.is_serial_protocol {
            return;
        }
        self.is_serial_protocol = true;
        self.buf_1 = BufferData {
            buf: RingBuf::new(1),
            tcp_meta: vec![],
            base_seq: None,
            max_frame: 0,
        };
    }

    pub fn set_seq(&mut self, seq: u32, direction: u8) {
        match direction {
            DIRECTION_C2S => self.buf_0.base_seq = Some(seq),
            DIRECTION_S2C => self.buf_1.base_seq = Some(seq),
            _ => unreachable!(),
        }
    }

    pub fn buf_is_empty(&self, direction: u8) -> bool {
        match direction {
            DIRECTION_C2S => self.buf_0.is_empty(),
            DIRECTION_S2C => self.buf_1.is_empty(),
            _ => unreachable!(),
        }
    }

    pub fn reassemble_non_serial(
        &mut self,
        seq: u32,
        payload: &[u8], // payload must not prune in the param
        direction: u8,
    ) -> TcpReassembleResult {
        match direction {
            DIRECTION_C2S => self.buf_0.reassemble(seq, payload),
            DIRECTION_S2C => self.buf_1.reassemble(seq, payload),
            _ => unreachable!(),
        }
    }

    pub fn reassemble_serial(
        &mut self,
        seq: u32,
        payload: &[u8], // payload must not prune in the param
        direction: u8,
    ) -> TcpReassembleResult {
        let buf = &mut self.buf_0;

        if self.current_direction.is_none() {
            let r = buf.reassemble(seq, payload);
            if !buf.is_empty() {
                self.current_direction = Some(direction);
            }
            r
        } else {
            let r = if self.current_direction.unwrap() == direction {
                let r = buf.reassemble(seq, payload);
                if !buf.is_empty() {
                    self.current_direction = Some(direction);
                }
                r
            } else {
                let f = buf.flush_all_buf();
                let mut r = buf.reassemble(seq, payload);
                if !buf.is_empty() {
                    self.current_direction = Some(direction);
                }

                let _ = r.as_mut().map_err(|e| match e {
                    TcpReassembleError::BufferFlush(d) => {
                        d.extend(f);
                    }
                    _ => {}
                });
                r
            };
            r
        }
    }
}
