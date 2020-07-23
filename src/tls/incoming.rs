use super::{
    CreateAcceptor, Handshake, MaybeTls, MaybeTlsSettings, MaybeTlsStream, PeerAddress,
    Result as TlsResult, TcpBind, TlsError, TlsSettings,
};
use bytes05::{Buf, BufMut};
use futures::{future::BoxFuture, FutureExt, Stream, StreamExt};
use openssl::ssl::{SslAcceptor, SslMethod};
use pin_project::pin_project;
use snafu::ResultExt;
use std::{
    mem::MaybeUninit,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    net::{tcp::Incoming, TcpListener, TcpStream},
};
use tokio_openssl::{HandshakeError, SslStream};

impl TlsSettings {
    pub(crate) fn acceptor(&self) -> TlsResult<SslAcceptor> {
        match self.identity {
            None => Err(TlsError::MissingRequiredIdentity),
            Some(_) => {
                let mut acceptor =
                    SslAcceptor::mozilla_intermediate(SslMethod::tls()).context(CreateAcceptor)?;
                self.apply_context(&mut acceptor)?;
                Ok(acceptor.build())
            }
        }
    }
}

impl MaybeTlsSettings {
    pub(crate) async fn bind(&self, addr: &SocketAddr) -> TlsResult<MaybeTlsListener> {
        let listener = TcpListener::bind(addr).await.context(TcpBind)?;

        let acceptor = match self {
            Self::Tls(tls) => Some(tls.acceptor()?),
            Self::Raw(()) => None,
        };

        Ok(MaybeTlsListener { listener, acceptor })
    }
}

// #[pin_project]
// pub(crate) struct MaybeTlsIncoming {
//     listener: MaybeTlsIncoming,
//     stream: Option<Incoming>,
// }

// impl Stream for MaybeTlsIncoming {
//     type Item = TlsResult<MaybeTlsIncomingStream<TcpStream>>;

//     fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         let s = Pin::new(self.project().incoming.as_mut());
//         Poll::Pending
//         // let (socket, _) = ready!(self.inner.poll_accept(cx))?;
//         // Poll::Ready(Some(Ok(socket)))
//     }
// }

pub(crate) struct MaybeTlsListener {
    listener: TcpListener,
    acceptor: Option<SslAcceptor>,
}

impl MaybeTlsListener {
    // pub(crate) fn incoming(self) -> MaybeTlsIncoming {
    //     let incoming = MaybeTlsIncoming {
    //         listener: self,
    //         incoming: None,
    //     };
    //     incoming.incoming = Some(incoming.listener.incoming());
    //     incoming
    //     // let acceptor = self.acceptor.clone();
    //     // self.listener
    //     //     .incoming()
    //     //     .map(move |connection| match connection {
    //     //         Ok(stream) => MaybeTlsIncomingStream::new(stream, acceptor.clone()),
    //     //         Err(source) => Err(TlsError::IncomingListener { source }),
    //     //     })
    // }

    pub(crate) fn incoming(
        &mut self,
    ) -> impl Stream<Item = TlsResult<MaybeTlsIncomingStream<TcpStream>>> + '_ {
        let acceptor = self.acceptor.clone();
        self.listener
            .incoming()
            .map(move |connection| match connection {
                Ok(stream) => MaybeTlsIncomingStream::new(stream, acceptor.clone()),
                Err(source) => Err(TlsError::IncomingListener { source }),
            })
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }
}

impl From<TcpListener> for MaybeTlsListener {
    fn from(listener: TcpListener) -> Self {
        Self {
            listener,
            acceptor: None,
        }
    }
}

#[pin_project]
pub struct MaybeTlsIncomingStream<S> {
    #[pin]
    state: StreamState<S>,
    // BoxFuture doesn't allow access to the inner stream, but users
    // of MaybeTlsIncomingStream want access to the peer address while
    // still handshaking, so we have to cache it here.
    peer_addr: SocketAddr,
}

#[pin_project(project = StreamStateProj)]
enum StreamState<S> {
    Accepted(#[pin] MaybeTlsStream<S>),
    Accepting(BoxFuture<'static, Result<SslStream<S>, HandshakeError<S>>>),
}

impl<S> MaybeTlsIncomingStream<S> {
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// None if connection still hasen't been established.
    pub fn get_ref(&self) -> Option<&S> {
        match &self.state {
            StreamState::Accepted(stream) => Some(match stream {
                MaybeTls::Raw(s) => s,
                MaybeTls::Tls(s) => s.get_ref(),
            }),
            StreamState::Accepting(_) => None,
        }
    }
}

impl MaybeTlsIncomingStream<TcpStream> {
    pub(super) fn new(stream: TcpStream, acceptor: Option<SslAcceptor>) -> TlsResult<Self> {
        let peer_addr = stream.peer_addr().context(PeerAddress)?;
        let state = match acceptor {
            Some(acceptor) => StreamState::Accepting(
                async move { tokio_openssl::accept(&acceptor, stream).await }.boxed(),
            ),
            None => StreamState::Accepted(MaybeTlsStream::Raw(stream)),
        };
        Ok(Self { peer_addr, state })
    }

    pub(crate) async fn handshake(&mut self) -> TlsResult<()> {
        if let StreamState::Accepting(fut) = &mut self.state {
            let stream = fut.await.context(Handshake)?;
            self.state = StreamState::Accepted(MaybeTlsStream::Tls(stream));
        }

        Ok(())
    }
}

impl<S> StreamState<S> {
    fn get_stream(self: Pin<&mut StreamState<S>>) -> Pin<&mut MaybeTlsStream<S>> {
        match self.project() {
            StreamStateProj::Accepted(stream) => stream,
            StreamStateProj::Accepting(_) => {
                unreachable!("Need call `MaybeTlsIncomingStream::handshake` first.")
            }
        }
    }
}

impl AsyncRead for MaybeTlsIncomingStream<TcpStream> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.project().state.get_stream().poll_read(cx, buf)
    }

    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        match &self.state {
            StreamState::Accepted(s) => s.prepare_uninitialized_buffer(buf),
            StreamState::Accepting(_) => {
                unreachable!("Need call `MaybeTlsIncomingStream::handshake` first.")
            }
        }
    }

    fn poll_read_buf<B: BufMut>(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut B,
    ) -> Poll<io::Result<usize>> {
        self.project().state.get_stream().poll_read_buf(cx, buf)
    }
}

impl AsyncWrite for MaybeTlsIncomingStream<TcpStream> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.project().state.get_stream().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.project().state.get_stream().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.project().state.get_stream().poll_shutdown(cx)
    }

    fn poll_write_buf<B: Buf>(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut B,
    ) -> Poll<io::Result<usize>> {
        self.project().state.get_stream().poll_write_buf(cx, buf)
    }
}
