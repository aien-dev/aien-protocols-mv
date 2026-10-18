//! PST1, the Pi-Spark task message: reader and writer for the fixed header.
//!
//! Spec: `specs/pi-spark-task/SPEC.md` (Draft v0.3, contract 0.1.0, wire
//! version 1). The C reference checker is `specs/pi-spark-task/tools/pst_verify.c`;
//! this crate must give the same verdict on the same bytes (the test in
//! `tests/vectors.rs` walks the shared vectors).
//!
//! Bounds are fixed: a message is 224 header bytes plus at most 800 payload
//! bytes. Decoding borrows the payload from the input and allocates nothing.
//! There is no JSON anywhere in the decode path.
//!
//! First cut (aien-protocols-mv#31): the header only. C6 (aien-protocols-mv#33)
//! adds the tool-call body (SPEC.md section 11): the 36-byte head of a
//! `tool_call_request` is checked in [`decode`], and [`TaskBody`] joins the
//! `tool_call_chunk` payloads into the INTERPLANE canonical request and checks
//! its digest. The side of the sender and the other session rules (section 10)
//! are not read here.
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// Bytes in the fixed header.
pub const HEADER_LEN: usize = 224;
/// Largest payload.
pub const MAX_PAYLOAD: usize = 800;
/// Largest message (header plus payload).
pub const MAX_MESSAGE: usize = HEADER_LEN + MAX_PAYLOAD;
/// The four bytes that open every message.
pub const MAGIC: [u8; 4] = *b"PST1";
/// The only wire version.
pub const VERSION: u8 = 1;
/// Highest message type (section 5).
pub const MAX_TYPE: u8 = 16;
/// The `request` type (an ordinary, non-tool task).
pub const TYPE_REQUEST: u8 = 1;
/// The `failed` type.
pub const TYPE_FAILED: u8 = 8;
/// The `cancelled` type.
pub const TYPE_CANCELLED: u8 = 9;
/// The `tool_call_request` type: opens a tool-call task (section 11).
pub const TYPE_TOOL_CALL_REQUEST: u8 = 15;
/// The `tool_call_chunk` type: the next piece of the canonical request.
pub const TYPE_TOOL_CALL_CHUNK: u8 = 16;
/// Bytes in a tool-call head: the INTERPLANE digest and the canonical length.
pub const TOOL_HEAD_LEN: usize = 36;
/// Longest INTERPLANE canonical request one tool-call task can carry.
pub const MAX_TOOL_REQUEST: u32 = 102_400;

const O_MAGIC: usize = 0;
const O_VERSION: usize = 4;
const O_TYPE: usize = 5;
const O_RES0: usize = 6;
const O_CAUSE: usize = 8;
const O_ORIGIN: usize = 40;
const O_OBJECTIVE: usize = 72;
const O_SUBJECT: usize = 104;
const O_PARENT: usize = 136;
const O_TASK: usize = 152;
const O_IDEM: usize = 168;
const O_ORDINAL: usize = 184;
const O_EFFECT: usize = 188;
const O_RES1: usize = 189;
const O_PLEN: usize = 190;
const O_DIGEST: usize = 192;

/// A refusal code from SPEC.md section 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BadMagic,
    BadVersion,
    Downgrade,
    BadType,
    WrongSide,
    BadLength,
    TrailingBytes,
    ReservedNonzero,
    NoCause,
    NoTask,
    NoObjective,
    DigestMismatch,
    BadEffectClass,
    SubjectMismatch,
    BadOrder,
    BadToolHead,
    ToolChunkSize,
    ToolDigestMismatch,
    ToolIncomplete,
    NotToolTask,
}

impl Refusal {
    /// The code name exactly as SPEC.md section 7 and the C checker print it.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::BadMagic => "PST_BAD_MAGIC",
            Refusal::BadVersion => "PST_BAD_VERSION",
            Refusal::Downgrade => "PST_DOWNGRADE",
            Refusal::BadType => "PST_BAD_TYPE",
            Refusal::WrongSide => "PST_WRONG_SIDE",
            Refusal::BadLength => "PST_BAD_LENGTH",
            Refusal::TrailingBytes => "PST_TRAILING_BYTES",
            Refusal::ReservedNonzero => "PST_RESERVED_NONZERO",
            Refusal::NoCause => "PST_NO_CAUSE",
            Refusal::NoTask => "PST_NO_TASK",
            Refusal::NoObjective => "PST_NO_OBJECTIVE",
            Refusal::DigestMismatch => "PST_DIGEST_MISMATCH",
            Refusal::BadEffectClass => "PST_BAD_EFFECT_CLASS",
            Refusal::SubjectMismatch => "PST_SUBJECT_MISMATCH",
            Refusal::BadOrder => "PST_BAD_ORDER",
            Refusal::BadToolHead => "PST_BAD_TOOL_HEAD",
            Refusal::ToolChunkSize => "PST_TOOL_CHUNK_SIZE",
            Refusal::ToolDigestMismatch => "PST_TOOL_DIGEST_MISMATCH",
            Refusal::ToolIncomplete => "PST_TOOL_INCOMPLETE",
            Refusal::NotToolTask => "PST_NOT_TOOL_TASK",
        }
    }
}

/// The decoded fixed header (SPEC.md section 4). Reserved bytes and the
/// magic are not stored: they have exactly one allowed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub msg_type: u8,
    pub cause_id: [u8; 32],
    pub origin_run_id: [u8; 32],
    pub objective_id: [u8; 32],
    pub subject_id: [u8; 32],
    pub parent_task_id: [u8; 16],
    pub task_id: [u8; 16],
    pub idempotence_key: [u8; 16],
    pub ordinal: u32,
    pub effect_class: u8,
    pub payload_len: u16,
    pub payload_digest: [u8; 32],
}

/// One accepted message: the header and the payload it borrows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

/// Why `encode` could not write a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The payload is longer than 800 bytes.
    PayloadTooLong,
    /// `payload_len` in the header differs from the payload given.
    LengthMismatch,
    /// The output buffer is too small.
    BufferTooSmall,
}

fn arr<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[at..at + N]);
    a
}

fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// Decode and check one message in the order of SPEC.md section 4.1, the
/// same order as the C checker, so the same bytes give the same code.
pub fn decode(b: &[u8]) -> Result<Message<'_>, Refusal> {
    // 1. length bounds
    if b.len() < HEADER_LEN || b.len() > MAX_MESSAGE {
        return Err(Refusal::BadLength);
    }
    // 2. magic
    if b[O_MAGIC..O_MAGIC + 4] != MAGIC {
        return Err(Refusal::BadMagic);
    }
    // 3. version
    if b[O_VERSION] < VERSION {
        return Err(Refusal::Downgrade);
    }
    if b[O_VERSION] > VERSION {
        return Err(Refusal::BadVersion);
    }
    // 4. type
    if b[O_TYPE] == 0 || b[O_TYPE] > MAX_TYPE {
        return Err(Refusal::BadType);
    }
    // 5. reserved
    if !all_zero(&b[O_RES0..O_RES0 + 2]) || b[O_RES1] != 0 {
        return Err(Refusal::ReservedNonzero);
    }
    // 6, 7. payload length against the bytes present
    let payload_len = u16::from_be_bytes(arr(b, O_PLEN));
    let body = &b[HEADER_LEN..];
    if body.len() < usize::from(payload_len) {
        return Err(Refusal::BadLength);
    }
    if body.len() > usize::from(payload_len) {
        return Err(Refusal::TrailingBytes);
    }
    // 8..11. field rules
    if b[O_EFFECT] > 2 {
        return Err(Refusal::BadEffectClass);
    }
    if all_zero(&b[O_CAUSE..O_CAUSE + 32]) {
        return Err(Refusal::NoCause);
    }
    if all_zero(&b[O_TASK..O_TASK + 16]) || all_zero(&b[O_IDEM..O_IDEM + 16]) {
        return Err(Refusal::NoTask);
    }
    let opens_task = b[O_TYPE] == TYPE_REQUEST || b[O_TYPE] == TYPE_TOOL_CALL_REQUEST;
    if opens_task && all_zero(&b[O_OBJECTIVE..O_OBJECTIVE + 32]) {
        return Err(Refusal::NoObjective);
    }
    // 12. payload digest
    let digest: [u8; 32] = Sha256::digest(body).into();
    if digest[..] != b[O_DIGEST..O_DIGEST + 32] {
        return Err(Refusal::DigestMismatch);
    }
    // 13. tool-call head
    if b[O_TYPE] == TYPE_TOOL_CALL_REQUEST {
        ToolCallHead::parse(body)?;
    }
    Ok(Message {
        header: Header {
            version: b[O_VERSION],
            msg_type: b[O_TYPE],
            cause_id: arr(b, O_CAUSE),
            origin_run_id: arr(b, O_ORIGIN),
            objective_id: arr(b, O_OBJECTIVE),
            subject_id: arr(b, O_SUBJECT),
            parent_task_id: arr(b, O_PARENT),
            task_id: arr(b, O_TASK),
            idempotence_key: arr(b, O_IDEM),
            ordinal: u32::from_be_bytes(arr(b, O_ORDINAL)),
            effect_class: b[O_EFFECT],
            payload_len,
            payload_digest: arr(b, O_DIGEST),
        },
        payload: body,
    })
}

/// Write one message into `out` and return the byte count. Fields are written
/// exactly as given; the digest is not recomputed (use [`payload_digest`]).
pub fn encode(h: &Header, payload: &[u8], out: &mut [u8]) -> Result<usize, EncodeError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(EncodeError::PayloadTooLong);
    }
    if usize::from(h.payload_len) != payload.len() {
        return Err(EncodeError::LengthMismatch);
    }
    let n = HEADER_LEN + payload.len();
    if out.len() < n {
        return Err(EncodeError::BufferTooSmall);
    }
    let o = &mut out[..n];
    o[..HEADER_LEN].fill(0);
    o[O_MAGIC..O_MAGIC + 4].copy_from_slice(&MAGIC);
    o[O_VERSION] = h.version;
    o[O_TYPE] = h.msg_type;
    o[O_CAUSE..O_CAUSE + 32].copy_from_slice(&h.cause_id);
    o[O_ORIGIN..O_ORIGIN + 32].copy_from_slice(&h.origin_run_id);
    o[O_OBJECTIVE..O_OBJECTIVE + 32].copy_from_slice(&h.objective_id);
    o[O_SUBJECT..O_SUBJECT + 32].copy_from_slice(&h.subject_id);
    o[O_PARENT..O_PARENT + 16].copy_from_slice(&h.parent_task_id);
    o[O_TASK..O_TASK + 16].copy_from_slice(&h.task_id);
    o[O_IDEM..O_IDEM + 16].copy_from_slice(&h.idempotence_key);
    o[O_ORDINAL..O_ORDINAL + 4].copy_from_slice(&h.ordinal.to_be_bytes());
    o[O_EFFECT] = h.effect_class;
    o[O_PLEN..O_PLEN + 2].copy_from_slice(&h.payload_len.to_be_bytes());
    o[O_DIGEST..O_DIGEST + 32].copy_from_slice(&h.payload_digest);
    o[HEADER_LEN..].copy_from_slice(payload);
    Ok(n)
}

/// The payload of a `tool_call_request` (SPEC.md section 11.2): the digest of
/// the INTERPLANE canonical request and its length in bytes, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolCallHead {
    /// SHA-256 of the canonical bytes; INTERPLANE writes it as `sha256:` + hex.
    pub interplane_digest: [u8; 32],
    /// Length of the canonical bytes, 1 to [`MAX_TOOL_REQUEST`].
    pub canonical_len: u32,
}

impl ToolCallHead {
    /// Read a head. Exactly 36 bytes, length 1 to 102400; anything else is
    /// `PST_BAD_TOOL_HEAD`.
    pub fn parse(payload: &[u8]) -> Result<Self, Refusal> {
        if payload.len() != TOOL_HEAD_LEN {
            return Err(Refusal::BadToolHead);
        }
        let canonical_len = u32::from_be_bytes(arr(payload, 32));
        if canonical_len == 0 || canonical_len > MAX_TOOL_REQUEST {
            return Err(Refusal::BadToolHead);
        }
        Ok(ToolCallHead {
            interplane_digest: arr(payload, 0),
            canonical_len,
        })
    }

    /// The digest as INTERPLANE prints it: `sha256:` and 64 lower-case hex digits.
    pub fn interplane_digest_string(&self) -> String {
        let mut s = String::with_capacity(71);
        s.push_str("sha256:");
        hex(&mut s, &self.interplane_digest);
        s
    }
}

/// A tool call being received: the head and the canonical bytes so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    head: ToolCallHead,
    bytes: Vec<u8>,
    verified: bool,
}

impl ToolCall {
    /// Start collecting the bytes the head announces.
    pub fn new(head: ToolCallHead) -> Self {
        ToolCall {
            head,
            bytes: Vec::with_capacity(head.canonical_len as usize),
            verified: false,
        }
    }

    /// The head this call was opened with.
    pub fn head(&self) -> &ToolCallHead {
        &self.head
    }

    /// Add one `tool_call_chunk` payload (section 11.3). Every chunk is
    /// exactly 800 bytes except the last, which is exactly what is left.
    /// Returns `Ok(true)` when the last chunk is in and the joined bytes match
    /// the head's digest.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Result<bool, Refusal> {
        if self.verified {
            return Err(Refusal::BadOrder);
        }
        let left = self.head.canonical_len as usize - self.bytes.len();
        if chunk.len() != left.min(MAX_PAYLOAD) {
            return Err(Refusal::ToolChunkSize);
        }
        self.bytes.extend_from_slice(chunk);
        if self.bytes.len() < self.head.canonical_len as usize {
            return Ok(false);
        }
        if payload_digest(&self.bytes) != self.head.interplane_digest {
            return Err(Refusal::ToolDigestMismatch);
        }
        self.verified = true;
        Ok(true)
    }

    /// The INTERPLANE canonical request, exactly as sent, once every chunk is
    /// in and the digest matched. `None` before that.
    pub fn canonical_bytes(&self) -> Option<&[u8]> {
        self.verified.then_some(&self.bytes[..])
    }
}

/// What a task carries, fixed by the message that opened it (section 11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskBody {
    /// Opened by `request`: an ordinary task. It never carries tool-call chunks.
    Chat,
    /// Opened by `tool_call_request`: carries one INTERPLANE canonical request.
    ToolCall(ToolCall),
}

impl TaskBody {
    /// The body a task opened by `m` carries, or `None` if `m` opens no task.
    pub fn open(m: &Message<'_>) -> Option<Result<Self, Refusal>> {
        match m.header.msg_type {
            TYPE_REQUEST => Some(Ok(TaskBody::Chat)),
            TYPE_TOOL_CALL_REQUEST => {
                Some(ToolCallHead::parse(m.payload).map(|h| TaskBody::ToolCall(ToolCall::new(h))))
            }
            _ => None,
        }
    }

    /// A `tool_call_chunk` for this task. A chunk on an ordinary task is
    /// `PST_NOT_TOOL_TASK`.
    pub fn chunk(&mut self, payload: &[u8]) -> Result<bool, Refusal> {
        match self {
            TaskBody::Chat => Err(Refusal::NotToolTask),
            TaskBody::ToolCall(call) => call.push_chunk(payload),
        }
    }

    /// May the Spark send `msg_type` for this task yet? Until the whole
    /// request is in and verified, only `failed` and `cancelled` are allowed
    /// (`PST_TOOL_INCOMPLETE`).
    pub fn check_spark(&self, msg_type: u8) -> Result<(), Refusal> {
        match self {
            TaskBody::ToolCall(call)
                if call.canonical_bytes().is_none()
                    && msg_type != TYPE_FAILED
                    && msg_type != TYPE_CANCELLED =>
            {
                Err(Refusal::ToolIncomplete)
            }
            _ => Ok(()),
        }
    }
}

/// SHA-256 of a payload, for filling `Header::payload_digest`.
pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

fn hex(out: &mut String, bytes: &[u8]) {
    const HX: &[u8; 16] = b"0123456789abcdef";
    for &x in bytes {
        out.push(char::from(HX[usize::from(x >> 4)]));
        out.push(char::from(HX[usize::from(x & 15)]));
    }
}

/// The verdict line in the exact format of `pst_verify FILE` and
/// `vectors/expected.txt`.
pub fn verdict_line(result: &Result<Message<'_>, Refusal>) -> String {
    let m = match result {
        Err(r) => return format!("refuse {}", r.code()),
        Ok(m) => &m.header,
    };
    let mut s = String::with_capacity(512);
    s.push_str(&format!(
        "ok type={} version={} cause=",
        m.msg_type, m.version
    ));
    hex(&mut s, &m.cause_id);
    s.push_str(" origin=");
    hex(&mut s, &m.origin_run_id);
    s.push_str(" objective=");
    hex(&mut s, &m.objective_id);
    s.push_str(" subject=");
    hex(&mut s, &m.subject_id);
    s.push_str(" parent=");
    hex(&mut s, &m.parent_task_id);
    s.push_str(" task=");
    hex(&mut s, &m.task_id);
    s.push_str(" idem=");
    hex(&mut s, &m.idempotence_key);
    s.push_str(&format!(
        " ordinal={} effect={} len={} digest=",
        m.ordinal, m.effect_class, m.payload_len
    ));
    hex(&mut s, &m.payload_digest);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Header, &'static [u8]) {
        let payload: &'static [u8] = b"hello";
        let h = Header {
            version: VERSION,
            msg_type: TYPE_REQUEST,
            cause_id: [1; 32],
            origin_run_id: [2; 32],
            objective_id: [3; 32],
            subject_id: [4; 32],
            parent_task_id: [0; 16],
            task_id: [5; 16],
            idempotence_key: [6; 16],
            ordinal: 0,
            effect_class: 1,
            payload_len: 5,
            payload_digest: payload_digest(payload),
        };
        (h, payload)
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let (h, p) = sample();
        let mut out = [0u8; MAX_MESSAGE];
        let n = encode(&h, p, &mut out).unwrap();
        let m = decode(&out[..n]).unwrap();
        assert_eq!(m.header, h);
        assert_eq!(m.payload, p);
    }

    #[test]
    fn encode_refuses_what_it_cannot_write() {
        let (mut h, p) = sample();
        let mut small = [0u8; HEADER_LEN];
        assert_eq!(encode(&h, p, &mut small), Err(EncodeError::BufferTooSmall));
        h.payload_len = 4;
        let mut out = [0u8; MAX_MESSAGE];
        assert_eq!(encode(&h, p, &mut out), Err(EncodeError::LengthMismatch));
        let long = [0u8; MAX_PAYLOAD + 1];
        assert_eq!(
            encode(&h, &long, &mut [0u8; 2048]),
            Err(EncodeError::PayloadTooLong)
        );
    }
    fn head_for(bytes: &[u8]) -> [u8; TOOL_HEAD_LEN] {
        let mut h = [0u8; TOOL_HEAD_LEN];
        h[..32].copy_from_slice(&payload_digest(bytes));
        h[32..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        h
    }

    #[test]
    fn tool_call_joins_chunks_and_checks_the_digest() {
        let canonical: Vec<u8> = (0..1700u32).map(|i| b'a' + (i % 26) as u8).collect();
        let head = ToolCallHead::parse(&head_for(&canonical)).unwrap();
        let mut call = ToolCall::new(head);
        assert_eq!(call.push_chunk(&canonical[..800]), Ok(false));
        assert_eq!(call.canonical_bytes(), None);
        assert_eq!(call.push_chunk(&canonical[800..1600]), Ok(false));
        assert_eq!(call.push_chunk(&canonical[1600..]), Ok(true));
        assert_eq!(call.canonical_bytes(), Some(&canonical[..]));
        assert_eq!(call.push_chunk(b"x"), Err(Refusal::BadOrder));

        let mut altered = canonical.clone();
        altered[5] ^= 1;
        let mut call = ToolCall::new(head);
        call.push_chunk(&altered[..800]).unwrap();
        call.push_chunk(&altered[800..1600]).unwrap();
        assert_eq!(
            call.push_chunk(&altered[1600..]),
            Err(Refusal::ToolDigestMismatch)
        );

        let mut call = ToolCall::new(head);
        assert_eq!(
            call.push_chunk(&canonical[..799]),
            Err(Refusal::ToolChunkSize)
        );
    }

    #[test]
    fn tool_head_is_exactly_digest_and_length() {
        let h = head_for(b"{}");
        assert!(ToolCallHead::parse(&h).is_ok());
        assert_eq!(ToolCallHead::parse(&h[..35]), Err(Refusal::BadToolHead));
        let mut extra = h.to_vec();
        extra.push(0);
        assert_eq!(ToolCallHead::parse(&extra), Err(Refusal::BadToolHead));
        let mut zero = h;
        zero[32..].fill(0);
        assert_eq!(ToolCallHead::parse(&zero), Err(Refusal::BadToolHead));
        let mut over = h;
        over[32..].copy_from_slice(&(MAX_TOOL_REQUEST + 1).to_be_bytes());
        assert_eq!(ToolCallHead::parse(&over), Err(Refusal::BadToolHead));
    }

    #[test]
    fn chat_tasks_carry_no_tool_chunks_and_spark_waits_for_the_whole_call() {
        let mut chat = TaskBody::Chat;
        assert_eq!(chat.chunk(b"{}"), Err(Refusal::NotToolTask));
        let head = ToolCallHead::parse(&head_for(b"{}")).unwrap();
        let mut tool = TaskBody::ToolCall(ToolCall::new(head));
        assert_eq!(tool.check_spark(2), Err(Refusal::ToolIncomplete));
        assert_eq!(tool.check_spark(TYPE_FAILED), Ok(()));
        assert_eq!(tool.chunk(b"{}"), Ok(true));
        assert_eq!(tool.check_spark(2), Ok(()));
    }
}
