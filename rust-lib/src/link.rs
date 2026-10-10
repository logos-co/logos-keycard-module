//! A link to a Keycard: APDUs to a smart-card reader over PC/SC, or over TCP to the Keycard
//! applet in jCardSim, in tests. `KEYCARD_SIMULATOR=host:port` picks the simulator.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use keycard_rs::{ApduCommand, ApduResponse, CardChannel, Error};

/// The CA that signs the simulator's card identity: the test CA of the applet's own tests. Only
/// the simulator's link trusts it; a reader trusts the CAs keycard-rs names for real cards.
pub const SIMULATOR_CA: [u8; 33] = [
    0x02, 0x58, 0x77, 0x22, 0x0a, 0xaa, 0xe6, 0xe5, 0x4a, 0x6f, 0x97, 0x46, 0x02, 0xd5, 0x99, 0x5c,
    0x0f, 0xe2, 0x4a, 0x3e, 0xa7, 0xdd, 0xab, 0xd8, 0x64, 0x4b, 0xec, 0x79, 0x5b, 0x9d, 0xa0, 0x07,
    0x43,
];

/// The simulator's name as a reader.
pub const SIMULATOR_READER: &str = "Keycard simulator";

/// How long one answer may take: a card computes, it never waits on a person.
const PATIENCE: Duration = Duration::from_secs(60);

/// A reader holding a card. `epoch` changes when a card is inserted again; `None` means the link
/// can't tell, so the card is read again each time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slot {
    pub reader: String,
    pub epoch: Option<u64>,
}

/// One session with the card in a reader. A PC/SC session resets the card when it ends, so no
/// verified PIN outlives it.
pub enum Channel {
    Tcp(TcpLink),
    #[cfg(feature = "pcsc")]
    Pcsc(PcscLink),
}

impl CardChannel for Channel {
    fn send(&mut self, cmd: &ApduCommand) -> Result<ApduResponse, Error> {
        match self {
            Channel::Tcp(t) => t.send(cmd),
            #[cfg(feature = "pcsc")]
            Channel::Pcsc(p) => p.send(cmd),
        }
    }

    fn is_connected(&self) -> bool {
        match self {
            Channel::Tcp(_) => true,
            #[cfg(feature = "pcsc")]
            Channel::Pcsc(p) => p.card.is_some(),
        }
    }
}

/// The readers this module can reach.
pub trait Readers: Send + Sync {
    /// The readers holding a card now.
    fn present(&self) -> Vec<Slot>;
    /// A session with the card in `reader`; `keep` leaves the card as it is when the session ends.
    fn connect(&self, reader: &str, keep: bool) -> Result<Channel, String>;
    /// The CAs a 4.0 card's identity must be signed by.
    fn trusted_cas(&self) -> Vec<[u8; 33]>;
}

/// APDUs over TCP: each one length-prefixed, its answer the data's length, the data and the
/// status word, as the simulator in `sim/` serves them.
pub struct TcpLink {
    stream: TcpStream,
}

impl TcpLink {
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        let _ = stream.set_nodelay(true);
        stream.set_read_timeout(Some(PATIENCE))?;
        Ok(TcpLink { stream })
    }

    /// Raw bytes in, the answer with its status word out.
    pub fn exchange(&mut self, apdu: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut out = (apdu.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(apdu);
        self.stream.write_all(&out)?;
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len)?;
        let mut answer = vec![0u8; u32::from_be_bytes(len) as usize + 2];
        self.stream.read_exact(&mut answer)?;
        Ok(answer)
    }
}

impl CardChannel for TcpLink {
    fn send(&mut self, cmd: &ApduCommand) -> Result<ApduResponse, Error> {
        ApduResponse::new(&self.exchange(&cmd.serialize())?)
    }

    fn is_connected(&self) -> bool {
        true
    }
}

/// The Keycard applet in jCardSim at `host:port`, as one reader that always holds the card.
pub struct Simulator {
    addr: String,
}

impl Simulator {
    pub fn new(addr: impl Into<String>) -> Self {
        Simulator { addr: addr.into() }
    }
}

impl Readers for Simulator {
    fn present(&self) -> Vec<Slot> {
        match TcpLink::connect(&self.addr) {
            Ok(_) => vec![Slot {
                reader: SIMULATOR_READER.into(),
                epoch: None,
            }],
            Err(_) => Vec::new(),
        }
    }

    fn connect(&self, _reader: &str, _keep: bool) -> Result<Channel, String> {
        TcpLink::connect(&self.addr)
            .map(Channel::Tcp)
            .map_err(|e| format!("{}: {e}", self.addr))
    }

    fn trusted_cas(&self) -> Vec<[u8; 33]> {
        vec![SIMULATOR_CA]
    }
}

/// A card in a PC/SC reader.
#[cfg(feature = "pcsc")]
pub struct PcscLink {
    card: Option<pcsc::Card>,
    keep: bool,
}

#[cfg(feature = "pcsc")]
impl CardChannel for PcscLink {
    fn send(&mut self, cmd: &ApduCommand) -> Result<ApduResponse, Error> {
        let card = self
            .card
            .as_ref()
            .ok_or_else(|| Error::io_other("the card's session is closed"))?;
        let mut buf = [0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let answer = card
            .transmit(&cmd.serialize(), &mut buf)
            .map_err(Error::io_other)?;
        ApduResponse::new(answer)
    }

    fn is_connected(&self) -> bool {
        self.card.is_some()
    }
}

#[cfg(feature = "pcsc")]
impl Drop for PcscLink {
    fn drop(&mut self) {
        if let Some(card) = self.card.take() {
            let how = if self.keep {
                pcsc::Disposition::LeaveCard
            } else {
                pcsc::Disposition::ResetCard
            };
            let _ = card.disconnect(how);
        }
    }
}

/// The smart-card readers PC/SC knows: pcscd on Linux, the system's service elsewhere.
#[cfg(feature = "pcsc")]
pub struct Pcsc {
    ctx: std::sync::Mutex<Option<pcsc::Context>>,
}

#[cfg(feature = "pcsc")]
impl Pcsc {
    pub fn new() -> Self {
        Pcsc {
            ctx: std::sync::Mutex::new(None),
        }
    }

    /// The context, established on first use and again after the service restarts.
    fn with_ctx<T>(
        &self,
        f: impl Fn(&pcsc::Context) -> Result<T, pcsc::Error>,
    ) -> Result<T, String> {
        let mut guard = self.ctx.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..2 {
            if guard.is_none() {
                *guard = Some(
                    pcsc::Context::establish(pcsc::Scope::User)
                        .map_err(|e| format!("PC/SC: {e}"))?,
                );
            }
            match f(guard.as_ref().expect("just made")) {
                Err(pcsc::Error::InvalidHandle)
                | Err(pcsc::Error::NoService)
                | Err(pcsc::Error::ServiceStopped) => *guard = None,
                other => return other.map_err(|e| format!("PC/SC: {e}")),
            }
        }
        Err("PC/SC: the smart-card service is not running".into())
    }
}

#[cfg(feature = "pcsc")]
impl Default for Pcsc {
    fn default() -> Self {
        Pcsc::new()
    }
}

#[cfg(feature = "pcsc")]
impl Readers for Pcsc {
    fn present(&self) -> Vec<Slot> {
        self.with_ctx(|ctx| {
            let readers = match ctx.list_readers_owned() {
                Ok(r) => r,
                Err(pcsc::Error::NoReadersAvailable) => return Ok(Vec::new()),
                Err(e) => return Err(e),
            };
            let mut states: Vec<pcsc::ReaderState> = readers
                .into_iter()
                .map(|r| pcsc::ReaderState::new(r, pcsc::State::UNAWARE))
                .collect();
            if states.is_empty() {
                return Ok(Vec::new());
            }
            match ctx.get_status_change(Duration::ZERO, &mut states) {
                Ok(()) | Err(pcsc::Error::Timeout) => {}
                Err(e) => return Err(e),
            }
            Ok(states
                .iter()
                .filter(|s| {
                    let st = s.event_state();
                    st.contains(pcsc::State::PRESENT) && !st.contains(pcsc::State::MUTE)
                })
                .map(|s| Slot {
                    reader: s.name().to_string_lossy().into_owned(),
                    epoch: Some(u64::from(s.event_count())),
                })
                .collect())
        })
        .unwrap_or_default()
    }

    fn connect(&self, reader: &str, keep: bool) -> Result<Channel, String> {
        let name = std::ffi::CString::new(reader).map_err(|e| e.to_string())?;
        let card =
            self.with_ctx(|ctx| ctx.connect(&name, pcsc::ShareMode::Shared, pcsc::Protocols::ANY))?;
        Ok(Channel::Pcsc(PcscLink {
            card: Some(card),
            keep,
        }))
    }

    fn trusted_cas(&self) -> Vec<[u8; 33]> {
        vec![keycard_rs::constants::DEFAULT_CA_PUBLIC_KEY]
    }
}

/// The readers to use: the simulator when `KEYCARD_SIMULATOR` names one, else PC/SC.
pub fn from_env() -> Box<dyn Readers> {
    match std::env::var("KEYCARD_SIMULATOR") {
        Ok(addr) if !addr.trim().is_empty() => Box::new(Simulator::new(addr.trim())),
        #[cfg(feature = "pcsc")]
        _ => Box::new(Pcsc::new()),
        #[cfg(not(feature = "pcsc"))]
        _ => Box::new(Simulator::new("")),
    }
}
