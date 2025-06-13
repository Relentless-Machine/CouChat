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
- **Testing**: JUnit 5, Mockito
- **CI/CD**: Jenkins (planned)

## Current Development Status

As of June 14, 2025:

*   The project is actively developing a **second prototype** focusing on core P2P functionality within a Local Area Network (LAN).
*   Key goals for this prototype include:
    *   LAN-based device discovery.
    *   End-to-end encrypted text and file messaging between two peers.
    *   Device Passkey based authentication (as a stand-in for full OAuth initially).
    *   Integration of the Java backend and React/Electron frontend into a single distributable package.
*   The `dev` branch is the main line for this ongoing development, incorporating learnings from previous prototypes.
*   A v0.1.0 frontend prototype (demonstrating UI flows) is available on the `release/v0.1.0-prototype` branch for historical reference.

## Modules (Backend - Key Services)

1.  **`com.couchat.auth.PasskeyAuthService`**: Manages device Passkey generation, registration, and user login/authentication.
2.  **`com.couchat.security.EncryptionService`**: Handles cryptographic operations, including RSA key pair management for identity and key exchange, AES session key generation, and end-to-end encryption/decryption of messages and files.
3.  **`com.couchat.p2p.DeviceDiscoveryService`**: Responsible for discovering other CouChat clients on the local network using multicast/broadcast.
4.  **`com.couchat.p2p.P2PConnectionManager`**: Manages the lifecycle of P2P connections with peers, including the secure handshake process (key exchange) and session establishment.
5.  **`com.couchat.messaging.MessageService`**: Handles the creation, processing (serialization/deserialization), and routing of different message types (text, file info, etc.).
6.  **`com.couchat.transfer.FileTransferService`**: Manages the mechanics of file transfers, including initiating transfers, chunking files, sending/receiving chunks, and tracking transfer status.
7.  **Repository Layer (`com.couchat.repository.*`)**: Provides data persistence for users, messages, conversations, etc., primarily using a local SQLite database.

## Getting Started

(To be updated with build and run instructions)

## Project Structure

```
couchat/
├── pom.xml                # Maven project configuration for backend
├── README.md              # This file
├── couchat_storage.db     # Local SQLite database file (gitignored typically)
├── couchat-frontend/      # React/Electron frontend application
│   ├── package.json
│   ├── electron-main.cjs
│   ├── vite.config.ts
│   └── src/
│       ├── main.tsx
│       └── App.tsx
└── src/                   # Java backend source
    ├── main/
    │   ├── java/
    │   │   └── com/
    │   │       └── couchat/
    │   │           ├── CouChatApplication.java
    │   │           ├── auth/              # Authentication (PasskeyAuthService)
    │   │           ├── conversation/      # Conversation management (future)
    │   │           ├── device/            # Device related services (future)
    │   │           ├── group/             # Group chat (future)
    │   │           ├── messaging/         # Message models, services, controllers
    │   │           ├── p2p/               # P2P discovery and connection management
    │   │           ├── repository/        # Data persistence interfaces and implementations
    │   │           ├── security/          # Encryption services
    │   │           ├── transfer/          # File transfer services and controllers
    │   │           └── user/              # User management (future)
    │   │           └── web/               # Web DTOs and some controllers
    │   └── resources/
    │       ├── application.properties
    │       └── db_schema.sql
    └── test/
        └── java/
            └── com/
                └── couchat/ # Unit and integration tests
```

## Design Documents

- Software Requirements Specification (SRS) - Provided
- Software Design Document (SDD) - Provided

## Next Steps

- **Backend**:
    - Solidify LAN device discovery and P2P connection stability.
    - Complete and rigorously test end-to-end encrypted text and file transfer.
    - Ensure robust Passkey authentication and session management.
    - Integrate database operations for storing messages and user Passkey information.
- **Frontend**:
    - Develop React components for user discovery, chat interface (text & file), and Passkey login.
    - Integrate frontend with backend APIs via Electron's IPC or local HTTP requests.
- **Integration & Packaging**:
    - Package the Java backend and React/Electron frontend into a single distributable application.
- **Testing**:
    - Conduct thorough end-to-end testing of the integrated prototype on a LAN.

## Contribution

(To be updated with contribution guidelines)
