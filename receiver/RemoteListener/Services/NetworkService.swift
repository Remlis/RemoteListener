// SPDX-License-Identifier: MIT
// NetworkService.swift — NWConnection TCP+TLS + RLP frame parsing

import Foundation
import Network

/// Service for connecting to a transmitter over TLS.
class NetworkService: ObservableObject {
    private var connection: NWConnection?

    @Published var isConnected = false
    @Published var remoteDeviceName: String?

    /// Connect to a transmitter at the given host:port.
    func connect(host: String, port: UInt16) {
        let endpointHost = NWEndpoint.Host(host)
        let endpointPort = NWEndpoint.Port(rawValue: port)!

        let tlsOptions = NWProtocolTLS.Options()
        // Set ALPN to "rl/1.0"
        let alpnData = "rl/1.0".data(using: .utf8)!
        sec_protocol_options_add_tls_application_protocol(tlsOptions.securityProtocolOptions, alpnData)

        // Custom certificate verification (verify Device ID fingerprint)
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions,
            { (_, trust, verifyCallback) in
                // TODO: Verify certificate SHA-256 fingerprint matches expected Device ID
                verifyCallback(true)
            }, DispatchQueue.main)

        let tcpOptions = NWProtocolTCP.Options()
        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)

        connection = NWConnection(host: endpointHost, port: endpointPort, using: parameters)

        connection?.stateUpdateHandler = { state in
            DispatchQueue.main.async {
                switch state {
                case .ready:
                    self.isConnected = true
                case .failed, .cancelled:
                    self.isConnected = false
                default:
                    break
                }
            }
        }

        connection?.start(queue: .main)
    }

    /// Disconnect from the transmitter.
    func disconnect() {
        connection?.cancel()
        connection = nil
        isConnected = false
    }
}
