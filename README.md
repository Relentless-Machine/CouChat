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
- **Database**: SQLite (for local encrypted storage)
- **Build Tool**: Maven
- **Version Control**: Git
- **Code Repository**: GitHub
- **Testing**: JUnit 5, Mockito
- **CI/CD**: Jenkins (planned)
- **Frontend**: Vue.js (initially, with React as a potential better choice) - To be developed separately.

## Modules (High-Level)

1.  **P2P Connection Management**: Handles NAT traversal (STUN/TURN) and establishes P2P connections.
2.  **Message Encryption & Storage**: Manages AES encryption for messages and RSA for key exchange. Stores messages securely in a local SQLite database.
3.  **Identity Authentication**: Implements OAuth2.0 for user authentication and device passkey binding.
4.  **Group Management**: Manages group creation, member administration, and message synchronization within groups.
5.  **Auxiliary Server Module (Signaling/Relay)**: Assists in P2P connection establishment and message relay when direct connection fails.

## Getting Started

(To be updated with build and run instructions)

## Project Structure

```
couchat/
├── pom.xml                # Maven project configuration
├── README.md              # This file
└── src/
    ├── main/
    │   ├── java/
    │   │   └── com/
    │   │       └── couchat/
    │   │           ├── CouChatApplication.java  # Spring Boot main application class
    │   │           ├── auth/                  # Authentication related classes
    │   │           │   └── AuthenticationInterface.java
    │   │           ├── group/                 # Group chat related classes
    │   │           │   └── GroupManagementInterface.java
    │   │           ├── p2p/                   # P2P connection management
    │   │           │   └── P2PConnectionInterface.java
    │   │           └── security/              # Encryption and local storage
    │   │               ├── MessageEncryptionInterface.java
    │   │               └── MessageStorageInterface.java
    │   └── resources/
    │       ├── application.properties # Spring Boot configuration
    │       └── db_schema.sql        # SQLite database schema
    └── test/
        └── java/
            └── com/
                └── couchat/
                    └── ... (unit tests)
```

## Design Documents

- Software Requirements Specification (SRS) - Provided
- Software Design Document (SDD) - Provided

## Next Steps

- Implement core functionalities for each module.
- Develop unit and integration tests.
- Set up CI/CD pipeline.
- Begin frontend development.

## Contribution

(To be updated with contribution guidelines)

