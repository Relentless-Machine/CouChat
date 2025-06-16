// F:/Git/CouChat/couchat-frontend/src/config.ts
// Read API_PORT from environment variable VITE_API_PORT, default to 8121 if not set
// For packaged app, this will always default to the fixed port the backend is started on by electron-main.
const defaultApiPort = 8121;
const apiPortFromEnv = import.meta.env.VITE_API_PORT;

const API_PORT = apiPortFromEnv ? parseInt(apiPortFromEnv) : defaultApiPort;
console.log(`Frontend API_PORT configured to: ${API_PORT}`); // Added log

export const API_BASE_URL = `http://localhost:${API_PORT}/api`;

export const API_BASE_URL_MESSAGES = `${API_BASE_URL}/messages`;
export const API_BASE_URL_AUTH = `${API_BASE_URL}/auth`;
export const API_BASE_URL_P2P = `${API_BASE_URL}/p2p`;
export const API_BASE_URL_FILES = `${API_BASE_URL}/files`;

// Add other base URLs as needed
