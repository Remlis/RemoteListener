//! RLP frame encoder/decoder.
//!
//! Frame format: `[2-byte header_len][Header protobuf][4-byte body_len][Body protobuf]`

use prost::Message;
use rl_core::proto::{Header, MessageType};

/// Maximum frame size (10 MB).
pub const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024;

/// Encode an RLP frame from a message type and body.
pub fn encode_frame(msg_type: MessageType, body: &[u8], compressed: bool) -> Vec<u8> {
    let header = Header {
        r#type: msg_type as i32,
        compressed,
    };
    let header_bytes = header.encode_to_vec();

    let mut frame = Vec::with_capacity(2 + header_bytes.len() + 4 + body.len());
    frame.extend_from_slice(&(header_bytes.len() as u16).to_be_bytes());
    frame.extend_from_slice(&header_bytes);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

/// Decoded RLP frame.
#[derive(Debug, Clone)]
pub struct DecodedFrame {
    pub header: Header,
    pub body: Vec<u8>,
}

/// Result of decoding a frame.
pub type FrameDecodeResult = Result<Option<(DecodedFrame, usize)>, FrameError>;

/// Decode an RLP frame from bytes. Returns the decoded frame and the number of bytes consumed.
pub fn decode_frame(data: &[u8]) -> FrameDecodeResult {
    if data.len() < 2 {
        return Ok(None);
    }

    let header_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + header_len + 4 {
        return Ok(None);
    }

    let header = Header::decode(&data[2..2 + header_len]).map_err(|_| FrameError::InvalidHeader)?;

    let body_len_start = 2 + header_len;
    let body_len = u32::from_be_bytes([
        data[body_len_start],
        data[body_len_start + 1],
        data[body_len_start + 2],
        data[body_len_start + 3],
    ]) as usize;

    let total_len = 2 + header_len + 4 + body_len;
    if data.len() < total_len {
        return Ok(None);
    }

    let body = data[body_len_start + 4..total_len].to_vec();

    Ok(Some((DecodedFrame { header, body }, total_len)))
}

/// Encode a typed message as an RLP frame.
pub fn encode_message<M: prost::Message>(msg_type: MessageType, msg: &M) -> Vec<u8> {
    let body = msg.encode_to_vec();
    encode_frame(msg_type, &body, false)
}

/// Decode a typed message from an RLP frame.
pub fn decode_message<M: prost::Message + Default>(frame: &DecodedFrame) -> Result<M, FrameError> {
    M::decode(frame.body.as_slice()).map_err(|_| FrameError::InvalidBody)
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("invalid frame header")]
    InvalidHeader,
    #[error("invalid frame body")]
    InvalidBody,
    #[error("frame too large")]
    TooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_core::proto::Hello;

    #[test]
    fn frame_roundtrip() {
        let hello = Hello {
            device_name: "TestDevice".into(),
            client_version: "0.1.0".into(),
            timestamp: 12345,
        };
        let frame_bytes = encode_message(MessageType::Hello, &hello);

        let (decoded, consumed) = decode_frame(&frame_bytes).unwrap().unwrap();
        assert_eq!(consumed, frame_bytes.len());

        let hello2: Hello = decode_message(&decoded).unwrap();
        assert_eq!(hello.device_name, hello2.device_name);
        assert_eq!(hello.timestamp, hello2.timestamp);
    }

    #[test]
    fn incomplete_frame_returns_none() {
        assert!(decode_frame(&[]).unwrap().is_none());
        assert!(decode_frame(&[0, 5]).unwrap().is_none()); // header_len=5 but no data
    }

    #[test]
    fn empty_body_roundtrip() {
        let frame_bytes = encode_frame(MessageType::Ping, &[], false);
        let (decoded, _) = decode_frame(&frame_bytes).unwrap().unwrap();
        assert!(decoded.body.is_empty());
    }
}
