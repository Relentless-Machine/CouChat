// F:\Git\CouChat\couchat-frontend\electron-main.js
const { app, BrowserWindow } = require('electron');
const path = require('node:path'); // Use 'node:path' for built-in module
const url = require('node:url');   // Use 'node:url' for built-in module

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require('electron-squirrel-startup')) {
  app.quit();
}

const isDev = process.env.NODE_ENV === 'development';

function createWindow() {
  // Create the browser window.
  const mainWindow = new BrowserWindow({
    width: 1200, // Increased width for better dev experience
    height: 800, // Increased height
    webPreferences: {
      preload: path.join(__dirname, 'electron-preload.cjs'), // Changed to .cjs
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  if (isDev) {
    // In development, load from the Vite dev server
    mainWindow.loadURL('http://localhost:5173'); // Ensure this port matches your Vite dev server
    // Open the DevTools.
    mainWindow.webContents.openDevTools();
  } else {
    // In production, load the index.html of the app.
    // The path should be relative to the app's root directory after packaging.
    // electron-builder typically puts the output in a 'dist' folder inside the packaged app.
    // For loading local files, it's often from the root of the app package.
    // Vite builds to 'dist' folder in the project root, which electron-builder will pick up.
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});
