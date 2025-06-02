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
    username TEXT,
    password_hash TEXT,
    oauth_token TEXT,
    device_id TEXT UNIQUE
);

CREATE TABLE groups (
    group_id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name TEXT,
    member_ids TEXT  -- 存储成员ID的逗号分隔列表
);

CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    user_id INTEGER,
    passkey TEXT
);

