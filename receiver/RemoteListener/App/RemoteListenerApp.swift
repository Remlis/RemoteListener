// SPDX-License-Identifier: MIT
// RemoteListenerApp.swift — iOS App entry point

import SwiftUI

@main
struct RemoteListenerApp: App {
    @StateObject private var store = TransmitterStore()

    var body: some Scene {
        WindowGroup {
            TransmittersView()
                .environmentObject(store)
        }
    }
}
