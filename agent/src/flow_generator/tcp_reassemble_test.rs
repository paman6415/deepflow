use public::ringbuf::RingBuf;

use crate::flow_generator::tcp_reassemble::{BufferData, TcpFragementMeta};

use super::tcp_reassemble::TcpReassembleError;

#[test]
fn test_reassemble() {
    let packets = [
        (
            TcpFragementMeta {
                seq: 1,
                payload_len: 2,
            },
            vec![0u8; 2],
        ),
        (
            TcpFragementMeta {
                seq: 3,
                payload_len: 3,
            },
            vec![1u8; 3],
        ),
        (
            TcpFragementMeta {
                seq: 6,
                payload_len: 4,
            },
            vec![2u8; 4],
        ),
        (
            TcpFragementMeta {
                seq: 10,
                payload_len: 5,
            },
            vec![3u8; 5],
        ),
        // tcp seq preservr in 15 - 20
        (
            TcpFragementMeta {
                seq: 20,
                payload_len: 5,
            },
            vec![4u8; 5],
        ),
    ];

    let consquent_data = {
        let mut v = vec![];
        for i in 0..4 as usize {
            v.extend(packets[i].1.clone());
        }
        v
    };

    let mut buf = BufferData {
        buf: RingBuf::new(32),
        tcp_meta: Vec::with_capacity(5),
        base_seq: None,
        max_frame: 5,
    };

    for (t, p) in packets.iter() {
        let _ = buf.reassemble(t.seq, p.as_slice());
    }
    assert_eq!(buf.base_seq.unwrap(), 1);

    assert_eq!(buf.get_consequent_idx().unwrap(), 3);

    let (payload, meta) = buf.pop_consequent_seq_data();
    assert_eq!(buf.base_seq.unwrap(), 15);
    assert_eq!(consquent_data, payload);

    for (idx, m) in meta.iter().enumerate() {
        assert_eq!(m, &packets[idx].0);
    }

    assert_eq!(buf.get_waitting_buf_len_before_first_frame().unwrap(), 5);
    assert_eq!(buf.drain_waitting_buf_len_before_first_frame(), 5);

    let (payload, mut meta) = buf.pop_consequent_seq_data();
    assert_eq!(buf.base_seq.unwrap(), 25);
    assert_eq!(meta.len(), 1);
    assert_eq!(packets.last().unwrap().1, payload);
    assert_eq!(packets.last().unwrap().0, meta.remove(0));
}

#[test]
fn test_bad_frame() {
    let packets = [
        (
            TcpFragementMeta {
                seq: 1,
                payload_len: 2,
            },
            vec![0u8; 2],
        ),
        (
            TcpFragementMeta {
                seq: 3,
                payload_len: 3,
            },
            vec![1u8; 3],
        ),
        // tcp seq preserve in 6-10
        (
            TcpFragementMeta {
                seq: 10,
                payload_len: 4,
            },
            vec![2u8; 4],
        ),
        (
            TcpFragementMeta {
                seq: 14,
                payload_len: 5,
            },
            vec![3u8; 5],
        ),
    ];

    let consquent_data = {
        let mut v = vec![];
        for i in 2..4 as usize {
            v.extend(packets[i].1.clone());
        }
        v
    };

    let mut buf = BufferData {
        buf: RingBuf::new(32),
        tcp_meta: Vec::with_capacity(5),
        base_seq: None,
        max_frame: 5,
    };

    for (t, p) in packets.iter() {
        let _ = buf.reassemble(t.seq, p.as_slice());
    }

    let (before_base_frame, p) = (
        TcpFragementMeta {
            seq: 0,
            payload_len: 1,
        },
        vec![0u8; 1],
    );

    match buf
        .reassemble(before_base_frame.seq, p.as_slice())
        .unwrap_err()
    {
        TcpReassembleError::FrameBeforeBase => {}
        _ => unreachable!(),
    }

    let (bad_frame, p) = (
        TcpFragementMeta {
            seq: 11,
            payload_len: 10,
        },
        vec![3u8; 10],
    );

    match buf.reassemble(bad_frame.seq, p.as_slice()).unwrap_err() {
        TcpReassembleError::BufferFlush(mut f) => {
            assert_eq!(f.len(), 1);
            let (payload, meta) = f.remove(0);
            assert_eq!(payload, consquent_data);
            assert_eq!(
                meta,
                (&packets[2..])
                    .iter()
                    .map(|m| m.0.clone())
                    .collect::<Vec<TcpFragementMeta>>()
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn test_loopback() {
    let packets = [
        (
            TcpFragementMeta {
                seq: u32::MAX - 9,
                payload_len: 13,
            },
            vec![0u8; 13],
        ),
        (
            TcpFragementMeta {
                seq: 3,
                payload_len: 3,
            },
            vec![1u8; 3],
        ),
        (
            TcpFragementMeta {
                seq: 6,
                payload_len: 4,
            },
            vec![2u8; 4],
        ),
        (
            TcpFragementMeta {
                seq: 10,
                payload_len: 5,
            },
            vec![3u8; 5],
        ),
        // tcp seq preserve  in 15 - 20
        (
            TcpFragementMeta {
                seq: 20,
                payload_len: 5,
            },
            vec![4u8; 5],
        ),
    ];

    let consquent_data = {
        let mut v = vec![];
        for i in 0..4 as usize {
            v.extend(packets[i].1.clone());
        }
        v
    };

    let mut buf = BufferData {
        buf: RingBuf::new(64),
        tcp_meta: Vec::with_capacity(5),
        base_seq: None,
        max_frame: 5,
    };

    for (t, p) in packets.iter() {
        let _ = buf.reassemble(t.seq, p.as_slice());
    }

    assert_eq!(buf.base_seq.unwrap(), packets[0].0.seq);

    assert_eq!(buf.get_consequent_idx().unwrap(), 3);

    let (payload, meta) = buf.pop_consequent_seq_data();
    assert_eq!(buf.base_seq.unwrap(), 15);
    assert_eq!(consquent_data, payload);

    for (idx, m) in meta.iter().enumerate() {
        assert_eq!(m, &packets[idx].0);
    }

    assert_eq!(buf.get_waitting_buf_len_before_first_frame().unwrap(), 5);

    let (payload, mut meta) = buf.pop_consequent_seq_data();

    assert_eq!(buf.base_seq.unwrap(), 25);
    assert_eq!(meta.len(), 1);
    assert_eq!(packets.last().unwrap().1, payload);
    assert_eq!(packets.last().unwrap().0, meta.remove(0));
}
