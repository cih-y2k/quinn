//! API for sending 0-RTT data

use std::mem;
use std::sync::atomic::Ordering;

use crate::{ConnectionError, IncomingStreams};
use futures::channel::oneshot;
use quinn_proto::Directionality;

/// Handle for sending data on an outgoing connection that has not yet been established
pub struct Connection {
    conn: crate::Connection,
    connected: oneshot::Receiver<()>,
}

impl Connection {
    pub(crate) fn new(conn: crate::Connection, connected: oneshot::Receiver<()>) -> Self {
        Self { conn, connected }
    }

    /// Complete the handshake
    pub async fn handshake(self) -> Result<(crate::Connection, IncomingStreams), ConnectionError> {
        await!(self.connected).unwrap();
        let incoming = IncomingStreams(self.conn.0.clone());
        incoming.0.inner.lock().unwrap().check_err(incoming.0.ch)?;
        Ok((self.conn, incoming))
    }

    /// Open a new outgoing bidirectional 0-RTT stream
    ///
    /// Note that no data can be received until the handshake completes.
    pub fn open_bi(&self) -> Option<BiStream> {
        let inner = &mut *self.conn.0.inner.lock().unwrap();
        let id = inner.endpoint.open(self.conn.0.ch, Directionality::Bi)?;
        Some(BiStream(crate::BiStream::new(self.conn.0.clone(), id)))
    }

    /// Open a new outgoing unidirectional 0-RTT stream
    pub fn open_uni(&self) -> Option<SendStream> {
        let inner = &mut *self.conn.0.inner.lock().unwrap();
        let id = inner.endpoint.open(self.conn.0.ch, Directionality::Uni)?;
        Some(SendStream(crate::SendStream::new(self.conn.0.clone(), id)))
    }
}

/// 0-RTT bidirectional stream
pub struct BiStream(crate::BiStream);

impl BiStream {
    /// Send `buf` without waiting for the handshake to complete.
    ///
    /// Returns `n < buf.len()` if congestion/flow control block further sending.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        write_0rtt(&mut self.0.send, buf)
    }

    /// Finish the stream without waiting for the handshake to complete.
    pub fn finish(&mut self) -> Result<(), WriteError> {
        finish_0rtt(&mut self.0.send)
    }

    /// Attempt conversion into a 1-RTT stream
    ///
    /// Failure indicates that no 0-RTT data was delivered; the application is responsible for
    /// retransmitting if necessary.
    pub fn upgrade(self) -> Result<crate::BiStream, UpgradeError> {
        upgrade_0rtt(&self.0.send)?;
        Ok(self.0)
    }
}

/// 0-RTT unidirectional stream
pub struct SendStream(crate::SendStream);

impl SendStream {
    /// Send `buf` without waiting for the handshake to complete.
    ///
    /// Returns `n < buf.len()` if congestion/flow control block further sending.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        write_0rtt(&mut self.0, buf)
    }

    /// Finish the stream without waiting for the handshake to complete.
    pub fn finish(&mut self) -> Result<(), WriteError> {
        finish_0rtt(&mut self.0)
    }

    /// Attempt conversion into a 1-RTT stream
    ///
    /// Failure indicates that no 0-RTT data was delivered; the application is responsible for
    /// retransmitting if necessary.
    pub fn upgrade(self) -> Result<crate::SendStream, UpgradeError> {
        upgrade_0rtt(&self.0)?;
        Ok(self.0)
    }
}

/// Errors arising from writing to a 0-RTT stream
#[derive(Debug, Clone)]
pub enum WriteError {
    /// No further data can be written on this stream at least until the handshake completes.
    Blocked,
    /// The handshake finished, and this stream must now be converted into 1-RTT form using its
    /// `upgrade` method.
    Upgrade,
}

/// Errors arising while converting a 0-RTT stream to a 1-RTT stream.
#[derive(Debug, Clone)]
pub enum UpgradeError {
    /// The server rejected all 0-RTT data
    ///
    /// All streams have been returned to their initial empty and unopened state.
    Rejected,
    /// The local application already closed this connection
    ConnectionClosed,
}

fn write_0rtt(stream: &mut crate::SendStream, buf: &[u8]) -> Result<usize, WriteError> {
    let inner = &mut *stream.conn.inner.lock().unwrap();
    if stream.conn.dead.load(Ordering::Relaxed)
        || !inner.endpoint.connection(stream.conn.ch).is_handshaking()
    {
        return Err(WriteError::Upgrade);
    }
    inner.wake();
    use crate::quinn::WriteError::*;
    match inner.endpoint.write(stream.conn.ch, stream.id, buf) {
        Ok(n) => Ok(n),
        Err(Blocked) => Err(WriteError::Blocked),
        Err(Stopped { .. }) => unreachable!(),
    }
}

fn finish_0rtt(stream: &mut crate::SendStream) -> Result<(), WriteError> {
    if mem::replace(&mut stream.finishing, true) {
        return Ok(());
    }
    let inner = &mut *stream.conn.inner.lock().unwrap();
    if stream.conn.dead.load(Ordering::Relaxed)
        || !inner.endpoint.connection(stream.conn.ch).is_handshaking()
    {
        return Err(WriteError::Upgrade);
    }
    inner.endpoint.finish(stream.conn.ch, stream.id);
    Ok(())
}

fn upgrade_0rtt(stream: &crate::SendStream) -> Result<(), UpgradeError> {
    if stream.conn.dead.load(Ordering::Relaxed) {
        return Err(UpgradeError::ConnectionClosed);
    }
    let inner = &mut *stream.conn.inner.lock().unwrap();
    if inner.endpoint.connection(stream.conn.ch).accepted_0rtt() {
        Ok(())
    } else {
        Err(UpgradeError::Rejected)
    }
}
