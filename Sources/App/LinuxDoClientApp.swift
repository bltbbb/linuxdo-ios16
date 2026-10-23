import SwiftUI

@main
struct LinuxDoClientApp: App {

    @StateObject private var auth = AuthStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(auth)
                .onOpenURL { url in
                    // User API Key 授权完成后，站点会 302 到 linuxdoclient://auth?payload=...
                    Task { await auth.handleAuthCallback(url: url) }
                }
        }
    }
}

struct RootView: View {

    @EnvironmentObject private var auth: AuthStore
    @State private var didRestore = false

    var body: some View {
        Group {
            if auth.isLoggedIn {
                TopicListView()
            } else {
                LoginView()
            }
        }
        .task {
            guard !didRestore else { return }
            didRestore = true
            await auth.restoreSession()
        }
    }
}
