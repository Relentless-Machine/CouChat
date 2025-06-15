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

As of June 16, 2025:

*   The project is focused on completing the **second prototype**, emphasizing core P2P functionality within a Local Area Network (LAN).
*   Backend development for this prototype is substantially complete, with key features like LAN-based device discovery, end-to-end encrypted text messaging, Passkey-based authentication, and foundational support for file transfer, read receipts, and replies having their core logic and tests in place.
*   The immediate priority is **frontend development (React/Electron)** to build a user interface that integrates with these backend capabilities.
*   Key goals for this prototype remain:
    *   Robust LAN-based device discovery and stable P2P connections.
    *   Fully functional end-to-end encrypted text messaging between two peers, including support for read receipts and replies.
    *   Basic end-to-end encrypted file transfer.
    *   Device Passkey based authentication.
    *   Integration of the Java backend and React/Electron frontend into a single distributable package.
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
│   │   └── vite.svg
│   ├── release_builds/         # Output directory for packaged Electron application (gitignored)
│   │   ├── CouChat Setup 0.0.0.exe # Example installer
│   │   └── win-unpacked/           # Example unpacked application
│   └── src/                    # Frontend source code (React + TypeScript)
│       ├── main.tsx            # React application entry point for the renderer
│       ├── App.tsx             # Root React component
│       ├── App.css               # Global styles for App component
│       ├── index.css             # Global styles
│       ├── vite-env.d.ts       # TypeScript definitions for Vite environment variables
│       ├── assets/             # Frontend static assets (images, svgs, etc.)
│       │   └── react.svg
│       ├── components/         # Reusable React components
│       │   ├── LoginForm.tsx
│       │   └── ProtectedRoute.tsx
│       ├── contexts/           # React Context API for global state management
│       │   └── AuthContext.tsx
│       ├── pages/              # Page-level React components
│       │   ├── ChatPage.tsx
│       │   └── LoginPage.tsx
│       └── services/           # Frontend services for API calls and business logic
│           ├── AuthService.ts
│           ├── MessageService.ts
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
