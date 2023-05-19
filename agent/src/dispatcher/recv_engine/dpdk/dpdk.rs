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

use std::ffi::CString;
use std::ptr::null_mut;
use std::slice::from_raw_parts_mut;
use std::time::Duration;

use libc::{c_char, c_int, c_uint, c_void};

use public::packet::Packet;

#[repr(C)]
pub struct RteMbuf {
    buf_addr: *mut c_void,
    iova: u64,
    data_off: u16,
    refcnt: u16,
    nb_segs: u16,
    port: u16,
    ol_flags: u64,
    packet_type: u32,
    pkt_len: u32,
    data_len: u16,
    vlan_tci: u16,
    rss: u64,
    vlan_tci_outer: u16,
    buf_len: u16,
    timestamp: u64,
}

unsafe impl Send for RteMbuf {}
unsafe impl Sync for RteMbuf {}

impl RteMbuf {
    fn to_packet(&self) -> Packet {
        let data = unsafe {
            from_raw_parts_mut(
                (self.buf_addr as *mut u8).add(self.data_off as usize),
                self.buf_len as usize,
            )
        };
        Packet {
            timestamp: Duration::from_secs(self.timestamp),
            if_index: 0,
            capture_length: self.buf_len as isize,
            data,
        }
    }
}

extern "C" {
    pub fn rte_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
    pub fn rte_ring_lookup(name: *mut c_char) -> *mut c_void;
    pub fn rte_pktmbuf_free(ptr: *mut c_void);
    pub fn rte_ring_dequeue(ring: *mut c_void, packet: *mut *mut RteMbuf) -> c_int;
    pub fn rte_ring_dequeue_bulk(
        ring: *mut c_void,
        packets: *mut *mut RteMbuf,
        n: c_uint,
        available: *mut c_uint,
    ) -> c_uint;
}

pub struct Dpdk {
    // TODO: cpu affinity
    core_id: u32,
    name: String,
    ring: *mut c_void,

    batch_index: usize,
    batch_count: usize,
    batch: [*mut RteMbuf; Self::BATCH_SIZE],
}

unsafe impl Send for Dpdk {}
unsafe impl Sync for Dpdk {}

impl Dpdk {
    const BATCH_SIZE: usize = 32;

    pub fn rte_eal_init(argc: i32, argv: Vec<String>) -> i32 {
        let mut args: Vec<*mut c_char> = argv
            .iter()
            .map(|x| CString::new(x.clone()).unwrap().into_raw())
            .collect();
        let retc: c_int = unsafe { rte_eal_init(argc as c_int, args.as_mut_ptr()) };
        let ret: i32 = retc as i32;
        ret
    }

    pub fn rte_ring_lookup(name: String) -> *mut c_void {
        let name = CString::new(name.clone()).unwrap().into_raw();
        let ring = unsafe { rte_ring_lookup(name) };
        ring
    }

    // pub fn rte_ring_dequeue(ring: *mut c_void, packet: &mut *mut RteMbuf) -> isize {
    //     let packet = packet.as_mut_ptr();
    //     unsafe { rte_ring_dequeue(ring, packet) as isize }
    // }

    pub fn rte_ring_dequeue_bulk(ring: *mut c_void, packets: &mut [*mut RteMbuf]) -> usize {
        let n = packets.len() as c_uint;
        let packets = packets.as_mut_ptr();
        unsafe { rte_ring_dequeue_bulk(ring, packets, n, null_mut::<c_uint>()) as usize }
    }

    pub fn new(name: String, core_id: u32) -> Dpdk {
        let _ = Self::rte_eal_init(
            5,
            vec![
                "deepflow-agent".to_string(),
                "--proc-type".to_string(),
                "secondary".to_string(),
                "-l".to_string(),
                core_id.to_string(),
            ],
        );
        let ring = Self::rte_ring_lookup(format!("{}_tx", &name));
        let ptr = null_mut::<RteMbuf>();

        Dpdk {
            core_id,
            name,
            ring,
            batch_index: 0,
            batch_count: 0,
            batch: [ptr; Self::BATCH_SIZE],
        }
    }

    pub fn read(&mut self) -> Option<Packet> {
        if self.batch_index < self.batch_count {
            let packet = unsafe { (&*self.batch[self.batch_index]).to_packet() };
            self.batch_index += 1;
            return Some(packet);
        }

        for i in 0..self.batch_count {
            Self::free_mbuf(self.batch[i]);
        }

        let n = Self::rte_ring_dequeue_bulk(self.ring, &mut self.batch);
        if n == 0 {
            return None;
        }
        self.batch_count = n;
        self.batch_index = 1;
        let packet = unsafe { (&*self.batch[0]).to_packet() };
        return Some(packet);
    }

    pub fn free_mbuf(packet: *mut RteMbuf) {
        unsafe { rte_pktmbuf_free(packet as *mut c_void) };
    }
}
