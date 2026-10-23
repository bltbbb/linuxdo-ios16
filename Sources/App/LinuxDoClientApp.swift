import SwiftUI

@main
struct LinuxDoClientApp: App {

    @StateObject private var auth = AuthStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(auth)
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
