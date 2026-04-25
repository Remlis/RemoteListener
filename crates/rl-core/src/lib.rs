//! Remote Listener — shared core: protocol definitions, Device ID, config.

pub mod config;
pub mod device_id;

/// Re-export generated protobuf types.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/rl.protocol.rs"));
}

#[cfg(test)]
mod proto_tests {
    use super::proto::*;
    use prost::Message;

    #[test]
    fn hello_roundtrip() {
        let msg = Hello {
            device_name: "TestDevice".into(),
            client_version: "0.1.0".into(),
            timestamp: 1234567890,
        };
        let bytes = msg.encode_to_vec();
        let decoded = Hello::decode(bytes.as_slice()).unwrap();
        assert_eq!(msg.device_name, decoded.device_name);
        assert_eq!(msg.client_version, decoded.client_version);
        assert_eq!(msg.timestamp, decoded.timestamp);
    }

    #[test]
    fn channel_info_roundtrip() {
        let msg = ChannelInfo {
            channel_id: "ch-001".into(),
            device_name: "Microphone".into(),
            device_uid: "uid-abc".into(),
            recording_enabled: true,
            is_active: true,
            bitrate: 32,
            recorded_bytes: 1024,
        };
        let bytes = msg.encode_to_vec();
        let decoded = ChannelInfo::decode(bytes.as_slice()).unwrap();
        assert_eq!(msg.channel_id, decoded.channel_id);
        assert_eq!(msg.recording_enabled, decoded.recording_enabled);
        assert_eq!(msg.bitrate, decoded.bitrate);
    }

    #[test]
    fn pair_request_roundtrip() {
        let msg = PairRequest {
            device_name: "iPhone".into(),
            public_key: vec![1u8; 32],
        };
        let bytes = msg.encode_to_vec();
        let decoded = PairRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(msg.device_name, decoded.device_name);
        assert_eq!(msg.public_key, decoded.public_key);
    }

    #[test]
    fn control_command_roundtrip() {
        let msg = ControlCommand {
            control_type: ControlType::SetChannelRecording as i32,
            channel_id: "ch-001".into(),
            payload: Some(control_command::Payload::RecordingEnabled(true)),
        };
        let bytes = msg.encode_to_vec();
        let decoded = ControlCommand::decode(bytes.as_slice()).unwrap();
        assert_eq!(msg.channel_id, decoded.channel_id);
        assert!(matches!(
            decoded.payload,
            Some(control_command::Payload::RecordingEnabled(true))
        ));
    }
}
