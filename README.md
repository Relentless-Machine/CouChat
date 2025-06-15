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
- **Build Tool**: Maven
- **Version Control**: Git
- **Code Repository**: GitHub
- **Testing**: JUnit 5, Mockito, Spring Security Test
- **CI/CD**: Jenkins (planned)

## Current Development Status

As of June 15, 2025:

*   The project is actively developing a **second prototype** focusing on core P2P functionality within a Local Area Network (LAN).
*   Backend tests for key features of this prototype, including LAN-based device discovery, end-to-end encrypted text/file messaging, and Passkey-based authentication, are now **passing**.
*   Key goals for this prototype remain:
    *   Robust LAN-based device discovery and stable P2P connections.
    *   Fully functional end-to-end encrypted text and file messaging between two peers.
    *   Device Passkey based authentication.
    *   Integration of the Java backend and React/Electron frontend into a single distributable package.
*   The `dev` branch is the main line for this ongoing development, incorporating recent work on database integration, Passkey authentication, and extensive test corrections.
*   A v0.1.0 frontend prototype (demonstrating UI flows) is available on the `release/v0.1.0-prototype` branch for historical reference.

## Modules (Backend - Key Services)

1.  **`com.couchat.auth.PasskeyAuthService`**: Manages device Passkey generation, registration, and user login/authentication.
2.  **`com.couchat.security.EncryptionService`**: Handles cryptographic operations, including RSA key pair management for identity and key exchange, AES session key generation, and end-to-end encryption/decryption of messages and files.
3.  **`com.couchat.p2p.DeviceDiscoveryService`**: Responsible for discovering other CouChat clients on the local network using multicast/broadcast.
4.  **`com.couchat.p2p.P2PConnectionManager`**: Manages the lifecycle of P2P connections with peers, including the secure handshake process (key exchange) and session establishment.
5.  **`com.couchat.messaging.service.MessageService`**: Handles the creation, processing (serialization/deserialization), and routing of different message types (text, file info, etc.). Interacts with repositories for message persistence.
6.  **`com.couchat.transfer.FileTransferService`**: Manages the mechanics of file transfers, including initiating transfers, chunking files, sending/receiving chunks, and tracking transfer status.
7.  **Repository Layer (`com.couchat.repository.*`)**: Provides data persistence for users (including Passkeys), messages, conversations, etc., primarily using a local SQLite database.

## Getting Started

(To be updated with build and run instructions for the integrated prototype)

## Project Structure

```
couchat/
├── pom.xml                     # Maven project configuration for backend
├── README.md                   # This file
├── couchat_storage.db          # Local SQLite database file (gitignored)
├── couchat-frontend/           # React/Electron frontend application
│   ├── package.json            # Frontend dependencies and scripts
│   ├── electron-main.cjs       # Electron main process
│   ├── electron-preload.cjs    # Electron preload script
│   ├── vite.config.ts          # Vite configuration for frontend build
│   ├── tsconfig.json           # Base TypeScript configuration for frontend
│   ├── index.html              # Main HTML for Electron renderer
│   ├── ...                     # Other frontend config files (ESLint, specific tsconfigs)
│   ├── public/                 # Static assets for frontend
│   └── src/                    # Frontend source code (React)
│       ├── main.tsx            # React application entry point
│       ├── App.tsx             # Root React component
│       ├── assets/             # Frontend assets (images, svgs)
│       ├── components/         # Reusable React components (e.g., LoginForm)
│       ├── contexts/           # React contexts (e.g., AuthContext)
│       ├── pages/              # Page-level components (e.g., ChatPage, LoginPage)
│       └── services/           # Frontend services (e.g., AuthService, MessageService)
└── src/                        # Java backend source
    ├── main/
    │   ├── java/
    │   │   └── com/
    │   │       └── couchat/
    │   │           ├── CouChatApplication.java # Spring Boot main application class
    │   │           ├── api/                # DTOs for general API responses/requests (under api/dto)
    │   │           ├── auth/               # Authentication (Passkey services, DTOs)
    │   │           ├── config/             # Spring Boot configurations (Security, Web)
    │   │           ├── conversation/       # Conversation related (controllers, models, services)
    │   │           ├── device/             # Device related (models, services)
    │   │           ├── group/              # Group chat related (controllers, models, services)
    │   │           ├── messaging/          # Core messaging (models, services)
    │   │           ├── p2p/                # Peer-to-peer connection management and discovery
    │   │           ├── repository/         # Data persistence (interfaces and JDBC implementations)
    │   │           ├── security/           # Cryptographic services
    │   │           ├── transfer/           # File transfer (controllers, models, services)
    │   │           ├── user/               # User management (controllers, models, services)
    │   │           └── web/                # Web layer specific (controllers, DTOs for web interaction)
    │   └── resources/              # Backend resources
    │       ├── application.properties # Spring Boot application properties
    │       ├── db_schema.sql      # SQLite database schema definition
    │       └── logback.xml        # Logging configuration
    └── test/                       # Backend tests
        └── java/
            └── com/
                └── couchat/        # Test packages mirroring main structure
                    ├── auth/
                    ├── group/
                    ├── p2p/
                    ├── security/
                    └── web/controller/ # Note: web/controller is the specific path for MessageControllerTest
```

## Design Documents

- Software Requirements Specification (SRS) - Provided
- Software Design Document (SDD) - Provided

## Next Steps

With backend core P2P and messaging tests passing:

- **Frontend Development**: 
    - Implement UI for LAN user discovery and initiating chats.
    - Develop the main chat interface for sending/receiving encrypted text and files.
    - Integrate Passkey generation and login UI flows.
    - Connect React components to backend APIs via Electron's IPC or local HTTP requests.
- **Backend Refinement (As Needed)**:
    - Further stabilize P2P connections based on integration testing.
    - Optimize file transfer for larger files if necessary.
- **Integration & Packaging**:
    - Package the Java backend (Spring Boot JAR) and React/Electron frontend into a single distributable application.
- **End-to-End Testing**:
    - Conduct thorough end-to-end testing of the integrated prototype on a LAN, covering all core features of the second prototype.

## Contribution

(To be updated with contribution guidelines)
