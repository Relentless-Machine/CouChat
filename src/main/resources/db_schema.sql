CREATE TABLE messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    message_content TEXT,
    encrypted BOOLEAN,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL, -- Made username explicitly NOT NULL
    password_hash TEXT,
    oauth_provider TEXT,          -- Added for OAuth provider (e.g., GOOGLE, MICROSOFT)
    oauth_id TEXT,                -- Added for user's unique ID from OAuth provider
    UNIQUE (oauth_provider, oauth_id) -- Ensure unique combination of provider and id
);

CREATE TABLE groups (
    group_id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name TEXT,
    member_ids TEXT  -- 存储成员ID的逗号分隔列表
);

CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,     -- Made user_id explicitly NOT NULL
    passkey_hash TEXT,            -- Renamed from passkey to passkey_hash
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Added created_at for tracking
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
