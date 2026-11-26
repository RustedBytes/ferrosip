//! UDP: N workers, each with its *own* socket bound to the same address via
//! SO_REUSEPORT. The kernel hashes each source 4-tuple to one socket, so all
//! packets of a given peer hit the same worker (good cache locality, no
//! cross-worker handoff, no dispatcher thread).
//!
//! Kamailio: `children=N` forks N processes per listen socket, each blocking in
//! `udp_rcv_loop()` (src/core/udp_server.c).

use crate::{Scratch, dispatch};
use sip_core::{Dest, Handler, Outbound, Proto};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub fn bind_reuseport(addr: SocketAddr, bufsize: usize) -> io::Result<UdpSocket> {
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_reuse_port(true)?;
    #[allow(clippy::let_underscore_must_use, reason = "best effort: the socket works without it")]
    let _ = s.set_recv_buffer_size(bufsize);
    #[allow(clippy::let_underscore_must_use, reason = "best effort: the socket works without it")]
    let _ = s.set_send_buffer_size(bufsize);
    s.bind(&addr.into())?;
    Ok(s.into())
}

/// Spawns one receive thread per socket; fails if a thread can't be started.
pub fn run_workers(socks: Vec<UdpSocket>, net: Arc<dyn Outbound>, handler: Arc<dyn Handler>) -> Result<Vec<JoinHandle<()>>, String> {
    socks
        .into_iter()
        .enumerate()
        .map(|(id, sock)| {
            let (h, net) = (handler.clone(), net.clone());
            thread::Builder::new()
                .name(format!("udp-worker-{id}"))
                .spawn(move || worker_loop(id, sock, net, h))
                .map_err(|e| format!("cannot start UDP worker thread {id}: {e}"))
        })
        .collect()
}

fn worker_loop(id: usize, sock: UdpSocket, net: Arc<dyn Outbound>, handler: Arc<dyn Handler>) {
    // Allocated once per worker: receive buffer, arena ("pkg memory"), lumps, output.
    let mut buf = vec![0u8; 65_535];
    let mut scratch = Scratch::default();
    let mut errors_in_a_row = 0u32;
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(r) => {
                errors_in_a_row = 0;
                r
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                sip_core::stats::inc(recv_errors());
                errors_in_a_row = errors_in_a_row.saturating_add(1);
                // A transient error is just counted. A persistent one (e.g. a
                // dead socket) would otherwise spin a core and flood the log:
                // log it once in a while and back off.
                if errors_in_a_row.is_power_of_two() {
                    sip_core::elog!("udp-worker {id}: recv: {e} ({errors_in_a_row} in a row)");
                }
                if errors_in_a_row >= 16 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                continue;
            }
        };
        let Some(pkt) = buf.get(..n) else { continue };
        dispatch(pkt, Dest::new(Proto::Udp, src), &*net, Some(&sock), &*handler, &mut scratch, id);
    }
}

fn recv_errors() -> &'static std::sync::atomic::AtomicI64 {
    static C: std::sync::OnceLock<&'static std::sync::atomic::AtomicI64> = std::sync::OnceLock::new();
    C.get_or_init(|| sip_core::stats::counter("udp", "recv_errors"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::Ctx;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering::Relaxed;
    use std::time::{Duration, Instant};

    struct NullNet;

    impl Outbound for NullNet {
        fn send(&self, _: &Dest, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
    }

    struct Seen(Mutex<std::sync::mpsc::Sender<SocketAddr>>);

    impl Handler for Seen {
        fn handle(&self, ctx: &mut Ctx<'_, '_>) {
            self.0.lock().unwrap().send(ctx.src.addr).unwrap();
        }
    }

    #[test]
    fn a_receive_error_is_counted_and_the_worker_keeps_going() {
        // A connected UDP socket reports the ICMP port-unreachable of its
        // own send as an error on the next receive.
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = closed.local_addr().unwrap();
        drop(closed);
        sock.connect(peer).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let errors = recv_errors();
        let before = errors.load(Relaxed);
        run_workers(vec![sock.try_clone().unwrap()], Arc::new(NullNet), Arc::new(Seen(Mutex::new(tx)))).unwrap();
        sock.send(b"x").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while errors.load(Relaxed) == before {
            assert!(Instant::now() < deadline, "no receive error counted");
            thread::yield_now();
        }
        // The same worker then receives the next message from that peer.
        let back = UdpSocket::bind(peer).unwrap();
        back.send_to(
            b"OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:a@b>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n",
            sock.local_addr().unwrap(),
        )
        .unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), peer);
        assert_eq!(errors.load(Relaxed) - before, 1);
    }
}
