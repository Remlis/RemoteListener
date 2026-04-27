// SPDX-License-Identifier: MIT
// BonjourBrowser.swift — mDNS service discovery for nearby transmitters

import Foundation
import Combine

/// A transmitter discovered via Bonjour/mDNS on the local network.
public struct DiscoveredTransmitter: Identifiable, Equatable {
    /// Unique ID based on service name + type.
    public let id: String
    /// The service name (typically the transmitter's device name).
    public let name: String
    /// Resolved host name (e.g. "MacBook.local.").
    public var hostName: String?
    /// Resolved IP address.
    public var ipAddress: String?
    /// Port number.
    public var port: UInt16?
    /// TXT record: device_id value.
    public var deviceID: String?
    /// Whether this service has been resolved to an address.
    public var isResolved: Bool { ipAddress != nil && port != nil }

    public init(name: String) {
        self.id = name
        self.name = name
    }

    public static func == (lhs: DiscoveredTransmitter, rhs: DiscoveredTransmitter) -> Bool {
        lhs.id == rhs.id
    }
}

/// Browses for `_rllistener._tcp` services on the local network via Bonjour.
public class BonjourBrowser: NSObject, ObservableObject {
    /// The mDNS service type to browse for.
    public static let serviceType = "_rllistener._tcp"

    /// Currently discovered transmitters.
    @Published public private(set) var discovered: [DiscoveredTransmitter] = []

    /// Whether the browser is actively searching.
    @Published public private(set) var isSearching = false

    private var browser: NetServiceBrowser?
    private var resolvingServices: [String: NetService] = [:]

    public override init() {}

    /// Start browsing for transmitters on the local network.
    public func startSearching() {
        guard !isSearching else { return }

        let browser = NetServiceBrowser()
        browser.delegate = self
        self.browser = browser
        browser.searchForServices(ofType: Self.serviceType, inDomain: "local.")
        isSearching = true
    }

    /// Stop browsing.
    public func stopSearching() {
        browser?.stop()
        browser = nil
        resolvingServices.removeAll()
        isSearching = false
    }

    /// Resolve a discovered transmitter to get its IP address and port.
    func resolveService(_ transmitter: DiscoveredTransmitter) {
        let service = NetService(domain: "local.",
                                 type: Self.serviceType,
                                 name: transmitter.name)
        service.delegate = self
        resolvingServices[transmitter.id] = service
        service.resolve(withTimeout: 5.0)
    }
}

// MARK: - NetServiceBrowserDelegate

extension BonjourBrowser: NetServiceBrowserDelegate {
    public func netServiceBrowser(_ browser: NetServiceBrowser,
                                   didFind service: NetService,
                                   moreComing: Bool) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }

            let discovered = DiscoveredTransmitter(name: service.name)

            // Avoid duplicates
            if !self.discovered.contains(where: { $0.id == discovered.id }) {
                self.discovered.append(discovered)
                // Start resolving the service to get IP/port
                self.resolveService(discovered)
            }
        }
    }

    public func netServiceBrowser(_ browser: NetServiceBrowser,
                                   didRemove service: NetService,
                                   moreComing: Bool) {
        DispatchQueue.main.async { [weak self] in
            self?.discovered.removeAll { $0.id == service.name }
        }
    }

    public func netServiceBrowser(_ browser: NetServiceBrowser,
                                   didNotSearch errorDict: [String: NSNumber]) {
        DispatchQueue.main.async { [weak self] in
            self?.isSearching = false
        }
    }
}

// MARK: - NetServiceDelegate (for resolution)

extension BonjourBrowser: NetServiceDelegate {
    public func netServiceDidResolveAddress(_ sender: NetService) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let id = sender.name

            // Extract IP address from addresses
            var ipAddress: String?
            if let addresses = sender.addresses {
                for addrData in addresses {
                    ipAddress = Self.extractIPAddress(from: addrData)
                    if ipAddress != nil { break }
                }
            }

            // Read TXT record for device_id
            var deviceID: String?
            if let txtRecordData = sender.txtRecordData() {
                let txtDict = NetService.dictionary(fromTXTRecord: txtRecordData)
                if let deviceIDData = txtDict["device_id"] {
                    deviceID = String(data: deviceIDData, encoding: .utf8)
                }
            }

            // Update the discovered transmitter
            if let index = self.discovered.firstIndex(where: { $0.id == id }) {
                self.discovered[index].hostName = sender.hostName
                self.discovered[index].ipAddress = ipAddress
                self.discovered[index].port = UInt16(sender.port)
                self.discovered[index].deviceID = deviceID
            }

            self.resolvingServices.removeValue(forKey: id)
        }
    }

    public func netService(_ sender: NetService,
                            didNotResolve errorDict: [String: NSNumber]) {
        DispatchQueue.main.async { [weak self] in
            self?.resolvingServices.removeValue(forKey: sender.name)
        }
    }

    /// Extract a dotted-decimal IP address from a sockaddr Data blob.
    private static func extractIPAddress(from data: Data) -> String? {
        let count = data.count
        guard count >= MemoryLayout<sockaddr>.size else { return nil }

        var addr = sockaddr()
        _ = data.withUnsafeBytes { ptr in
            memcpy(&addr, ptr.baseAddress!, MemoryLayout<sockaddr>.size)
        }

        if addr.sa_family == sa_family_t(AF_INET) {
            guard count >= MemoryLayout<sockaddr_in>.size else { return nil }
            var addrIn = sockaddr_in()
            _ = data.withUnsafeBytes { ptr in
                memcpy(&addrIn, ptr.baseAddress!, MemoryLayout<sockaddr_in>.size)
            }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &addrIn.sin_addr, &buffer, socklen_t(buffer.count))
            return String(cString: buffer)
        } else if addr.sa_family == sa_family_t(AF_INET6) {
            guard count >= MemoryLayout<sockaddr_in6>.size else { return nil }
            var addrIn6 = sockaddr_in6()
            _ = data.withUnsafeBytes { ptr in
                memcpy(&addrIn6, ptr.baseAddress!, MemoryLayout<sockaddr_in6>.size)
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &addrIn6.sin6_addr, &buffer, socklen_t(buffer.count))
            return String(cString: buffer)
        }
        return nil
    }
}
