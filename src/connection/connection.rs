use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{
    packet::{error::ProtocolError, packet::Packet},
    result::{QuicheError, QuicheResult},
};

use super::ConnectionState;

pub struct Connection {
    state: ConnectionState,
    // queue of incoming packets to be processed
    recv_buf: Vec<Vec<u8>>,
    // queue of outgoing packets to be sent
    send_buf: Vec<Packet>,
    socket: UdpSocket,
    peer_addr: SocketAddr,
    kill: Option<Sender<()>>,
}

impl Connection {
    pub async fn new(local_addr: SocketAddr, peer_addr: SocketAddr) -> QuicheResult<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect(peer_addr).await?;

        Ok(Self {
            state: ConnectionState::Closed,
            recv_buf: Vec::new(),
            send_buf: Vec::new(),
            socket,
            peer_addr,
            kill: None,
        })
    }

    pub async fn open(&mut self) -> QuicheResult<()> {
        self.state = ConnectionState::Handshake;
        let client_hello = Packet::create_client_hello(todo!(), todo!(), todo!(), todo!());
        self.socket.send(client_hello.encode()?.as_slice()).await?;

        let mut writer: Vec<u8> = vec![0; 1_024];
        let bytes_recv = self.socket.recv(writer.as_mut_slice()).await?;
        writer.truncate(bytes_recv);

        let server_hello = Packet::decode(&mut writer)?;

        Ok(())
    }

    pub async fn _f(&mut self) -> QuicheResult<()> {
        let (unsub_tx, mut unsub_rx) = tokio::sync::mpsc::channel::<()>(1);
        self.kill = Some(unsub_tx);
        self.state = ConnectionState::Connected;

        tokio::spawn({
            async move {
                loop {
                    tokio::select! {
                        _ = unsub_rx.recv() => {
                            break;
                        }
                        // _ = self.recv() => {
                        //     self.process().await.unwrap();
                        // }
                        // _ = self.send() => {
                        //     self.process().await.unwrap();
                        // }
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn close(&mut self) -> QuicheResult<()> {
        match self.state {
            ConnectionState::Connected => {
                self.state = ConnectionState::Closing;
                self.kill.take().unwrap().send(()).await?;
                self.state = ConnectionState::Closed;
                Ok(())
            }
            ConnectionState::Handshake => {
                // special kill here...
                unimplemented!()
            }
            _ => Ok(()),
        }
    }

    #[allow(dead_code)]
    async fn recv(&mut self) -> QuicheResult<()> {
        unimplemented!()
    }

    #[allow(dead_code)]
    async fn send(&mut self) -> QuicheResult<()> {
        unimplemented!()
    }

    #[allow(dead_code)]
    async fn process(&mut self) -> QuicheResult<()> {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn generate_token() -> QuicheResult<()> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_handshake() {
        // create server connection
        // create client connection
        // open client <> server connection
        // send `ClientHello` to server
        // recv `ServerHello` from server
    }

    #[tokio::test]
    async fn test_arbitrary() {
        // create server connection
        // create client connection
        // open client <> server connection
        // send `ClientHello` to server
        // recv `ServerHello` from server
        // send & process arbitrary packets between client <> server
        // ensure appropriate responses, state transitions, etc.
    }
}
