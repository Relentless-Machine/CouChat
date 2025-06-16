# CouChat - Encrypted P2P Communication Software

## Project Overview

CouChat is an encrypted peer-to-peer (P2P) communication software designed with a strong emphasis on security and privacy. It aims to provide users with a secure platform for exchanging messages and files without relying on a central server for message relay, thereby minimizing data exposure and single points of failure.

## Features (Based on SRS v1.0)

- **P2P Architecture**: Direct communication between users.
- **WireGuard-based VPN**: Secure VPN tunnels for data transmission, with NAT traversal.
- **End-to-End Encryption**: Zero-trust architecture ensuring message security in transit and at rest.
- **Offline Messaging**: Encrypted storage of offline messages, delivered chronologically when users are online. Real-time message status updates.
- **Group Chat**: BitTorrent-like strategy for group message synchronization and persistence.
- **Authentication**: Supports device passkey login and third-party OAuth (Microsoft, Google). Session validity tied to device usage.
- **Multimedia Support**: Transmission of text, audio, and files. Option to share messages outside the application.
- **Trusted Message Servers (Optional)**: Users can add trusted servers (connected via WireGuard VPN) for offline message forwarding, NAT traversal assistance, message capping, and potential extensions like message auditing.

## Tech Stack

- **Backend**: Java, Spring Boot
- **Frontend**: React, Electron
- **Database**: SQLite (for local encrypted storage)
- **Build Tool**: Maven (backend), npm/yarn (frontend)
- **Version Control**: Git
- **Code Repository**: GitHub
- **Testing**:
    - Backend: JUnit 5, Mockito, Spring Security Test
    - Frontend: (To be determined, e.g., Vitest, React Testing Library)
- **CI/CD**: Jenkins (planned)

## Current Development Status

As of June 17, 2025:

*   The **second prototype** is **complete and packaged**. This prototype emphasizes core P2P functionality within a Local Area Network (LAN), including LAN-based device discovery, end-to-end encrypted text messaging, Passkey-based authentication, foundational file transfer support, read receipts, and replies, with a basic integrated UI.
*   Backend development for this prototype's core features is substantially complete and tested.
*   The immediate priority is **enhancing the frontend (React/Electron)** by:
    *   Implementing robust **end-to-end encrypted file transfer capabilities**.
    *   Building out a more polished and user-friendly interface based on recent UI/UX feedback.
*   Key goals for this phase remain:
    *   Fully functional and user-friendly end-to-end encrypted file transfer.
    *   Significant UI/UX improvements for better usability and aesthetics.
    *   Continued stabilization of P2P connections and core messaging features.
    *   Maintaining an integrated and distributable application package.
*   The `dev` branch is the main line for this ongoing development.
*   A v0.1.0 frontend prototype (demonstrating UI flows) is available on the `release/v0.1.0-prototype` branch for historical reference.

## Modules (Backend - Key Services)

1.  **`com.couchat.auth.PasskeyAuthService`**: Manages device Passkey generation, registration, local persistence, and user login/authentication.
2.  **`com.couchat.security.EncryptionService`**: Handles cryptographic operations, including RSA key pair management for identity and key exchange, AES session key generation, and end-to-end encryption/decryption of messages and files.
3.  **`com.couchat.p2p.DeviceDiscoveryService`**: Responsible for discovering other CouChat clients on the local network using multicast/broadcast and advertising this client's presence (User ID, IP, service port).
4.  **`com.couchat.p2p.P2PConnectionManager`**: Manages the lifecycle of P2P connections with peers, including listening for incoming connections, initiating outgoing connections, and performing the secure handshake process (key exchange) to establish an encrypted session.
5.  **`com.couchat.messaging.service.MessageService`**: Handles the creation, processing (serialization/deserialization), persistence, and routing of different message types (text, file info, read receipts, replies, etc.). Interacts with repositories for message and conversation persistence.
6.  **`com.couchat.transfer.FileTransferService`**: Manages the mechanics of file transfers, including initiating transfers (sending `FileInfo`), handling acceptance, chunking files, sending/receiving `FileChunk` messages, and tracking transfer status.
7.  **Repository Layer (`com.couchat.repository.*` and `com.couchat.repository.impl.*`)**: Provides data persistence for users (including Passkeys), messages, conversations, groups, devices, and file transfer metadata, primarily using a local SQLite database (`couchat_storage.db`) via JDBC.

## Getting Started

(To be updated with build and run instructions for the integrated prototype)

## Project Structure

```
couchat/
├── pom.xml                     # Maven project configuration for backend
├── README.md                   # This file
├── auth_manager_standalone.db  # Local SQLite database file (gitignored)
├── couchat_storage.db          # Local SQLite database file (gitignored)
├── couchat-frontend/           # React/Electron frontend application
│   ├── package.json            # Frontend dependencies and scripts (npm/yarn)
│   ├── electron-main.cjs       # Electron main process script
│   ├── electron-preload.cjs    # Electron preload script for renderer
│   ├── vite.config.ts          # Vite configuration for frontend build and dev server
│   ├── tsconfig.json           # Base TypeScript configuration for frontend
│   ├── tsconfig.app.json       # TypeScript configuration for the app (renderer)
│   ├── tsconfig.node.json      # TypeScript configuration for Node.js parts (e.g., Electron main)
│   ├── eslint.config.js        # ESLint configuration for code linting
│   ├── index.html              # Main HTML entry point for the Electron renderer process
│   ├── public/                 # Static assets served by Vite (e.g., vite.svg)
│   │   ├── icon.ico            # Application icon
│   │   └── vite.svg
│   ├── release_builds/         # Output directory for packaged Electron application (gitignored)
│   │   ├── CouChat Setup 0.1.0.exe # Example installer
│   │   └── win-unpacked/           # Example unpacked application
│   └── src/                    # Frontend source code (React + TypeScript)
│       ├── main.tsx            # React application entry point for the renderer
│       ├── App.tsx             # Root React component
│       ├── App.css               # Global styles for App component
│       ├── index.css             # Global styles
│       ├── vite-env.d.ts       # TypeScript definitions for Vite environment variables
│       ├── config.ts           # Configuration file for frontend settings (e.g., API URLs)
│       ├── assets/             # Frontend static assets (images, svgs, etc.)
│       │   └── react.svg
│       ├── components/         # Reusable React components
│       │   ├── LoginForm.tsx
│       │   ├── ProtectedRoute.tsx
│       │   └── UserDiscoveryPanel.tsx
│       ├── contexts/           # React Context API for global state management
│       │   └── AuthContext.tsx
│       ├── pages/              # Page-level React components
│       │   ├── ChatPage.tsx
│       │   └── LoginPage.tsx
│       └── services/           # Frontend services for API calls and business logic
│           ├── AuthService.ts
│           ├── MessageService.ts
│           ├── P2PService.ts
│           └── FileTransferService.ts # (Planned)
└── src/                        # Java backend source code (Maven structure)
    ├── main/
    │   ├── java/
    │   │   └── com/
    │   │       └── couchat/    # Base package for the backend application
    │   │           ├── CouChatApplication.java # Spring Boot main application class
    │   │           ├── api/dto/            # Data Transfer Objects for general API use
    │   │           ├── auth/               # Authentication (Passkey services, DTOs, controllers)
    │   │           ├── config/             # Spring Boot configurations (Security, Web CORS)
    │   │           ├── conversation/       # Conversation management (controllers, models, services)
    │   │           ├── device/             # Device management (models, services)
    │   │           ├── group/              # Group chat management (controllers, models, services)
    │   │           ├── messaging/          # Core messaging logic (models, services)
    │   │           ├── p2p/                # Peer-to-peer connection, discovery, and handshake
    │   │           ├── repository/         # Data persistence (interfaces and JDBC implementations)
    │   │           ├── security/           # Cryptographic services (RSA, AES)
    │   │           ├── transfer/           # File transfer logic (controllers, models, services)
    │   │           ├── user/               # User management (controllers, models, services)
    │   │           └── web/                # Web layer specific (e.g., MessageController, DTOs)
    │   └── resources/              # Backend resources
    │       ├── application.properties # Spring Boot application properties
    │       ├── db_schema.sql      # SQLite database schema definition
    │       └── logback.xml        # Logging configuration (Logback)
    └── test/                       # Backend unit and integration tests
        └── java/
            └── com/
                └── couchat/        # Test packages mirroring main source structure
                    ├── auth/
                    ├── group/
                    ├── p2p/
                    ├── security/
                    └── web/controller/
└── target/                     # Maven build output directory (gitignored)
    ├── classes/                # Compiled backend classes and resources
    ├── surefire-reports/       # Test execution reports
    └── ...                     # Other Maven build artifacts (e.g., JAR file)
```

## Design Documents

- Software Requirements Specification (SRS) - Provided
- Software Design Document (SDD) - Provided

## Next Steps

With the second prototype packaged and core backend functionalities in place:

- **Frontend Development**:
    - **Implement robust end-to-end encrypted file transfer**:
        - Develop the UI for selecting, sending, and receiving files.
        - Show file transfer progress, and handle cancellations and errors.
        - Integrate with the backend `FileTransferService`.
    - **Implement comprehensive UI/UX enhancements**:
        - **User Identification**:
            - Replace UUIDs with user-configurable nicknames in chat windows and user lists.
            - Add an avatar system (e.g., default colored avatars with initials, with potential for custom image uploads later).
        - **Chat Interface**:
            - Implement distinct styling (e.g., color, alignment) for sender and receiver message bubbles.
            - Optimize message timestamp display (e.g., group by time, show on hover, or less frequently).
            - Add scroll-to-load functionality for fetching older messages.
            - Enhance the message input area with a clear border and a distinct send button.
            - Add placeholder buttons/icons for future features like emojis.
        - **Sidebar/User List**:
            - Change "Discover Users on LAN" to a more intuitive label like "Nearby Users" or "Online Users".
            - Display user nicknames instead of full UUIDs in the user list.
            - Add visual online status indicators (e.g., a green dot).
            - Implement a "Recent Chats" list for quick access.
            - Replace the "Refresh User List" text button with an icon button.
        - **General Layout & Theming**:
            - Increase padding and spacing for a cleaner, less cluttered look.
            - Review and modernize the color scheme for better visual harmony.
            - Plan and implement a night mode/dark theme option.
            - Improve the visual styling of scrollbars.
    - Integrate Passkey generation and login UI flows if further enhancements are needed beyond the current prototype.
    - Connect React components to backend APIs via Electron's IPC or local HTTP requests for new functionalities.
- **Backend Refinement (As Needed)**:
    - Further stabilize P2P connections and messaging based on ongoing integration testing with the enhanced frontend.
    - Optimize file transfer mechanisms for larger files or concurrent transfers if performance issues arise.
    - Continue backend enhancements based on the SRS and SDD, including considerations for future features like advanced group chat functionalities, trusted server interactions, and compliance requirements (e.g., exploring PRE for secure data sharing with authorized entities).
- **Integration & Packaging**:
    - Maintain and refine the build process for the integrated distributable application (Electron with bundled Java backend).
- **End-to-End Testing**:
    - Conduct thorough end-to-end testing of the newly implemented file transfer feature and all UI/UX changes on a LAN.
    - Test various scenarios, including different file types, sizes, and network conditions.

## Contribution

(To be updated with contribution guidelines)
