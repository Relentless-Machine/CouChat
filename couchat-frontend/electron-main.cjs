// F:\Git\CouChat\couchat-frontend\electron-main.js
const { app, BrowserWindow, dialog } = require('electron');
const path = require('node:path'); // Use 'node:path' for built-in module
const url = require('node:url');   // Use 'node:url' for built-in module
const { spawn, execSync } = require('node:child_process');
const fs = require('node:fs'); // Added fs

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require('electron-squirrel-startup')) {
  app.quit();
}

const isDev = process.env.NODE_ENV === 'development';

let backendProcess = null;
const backendPort = 8121; // Fixed backend port
const jarName = 'couchat-1.0-SNAPSHOT.jar'; // Ensure this matches your actual JAR file name

function checkJava() {
  try {
    execSync('java -version');
    console.log('Java check: Java is installed.');
    return true;
  } catch (error) {
    console.error('Java check: Java is not installed or not found in PATH.', error.message);
    dialog.showErrorBox(
      'Java Not Found',
      'Java Runtime Environment (JRE) is required to run this application, but it was not found on your system. Please install Java (version 11 or higher) and ensure it is added to your system PATH.'
    );
    return false;
  }
}

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
    // Open the DevTools
    mainWindow.webContents.openDevTools();
  } else {
    // In production, load the index.html of the app.
    const indexPath = path.join(__dirname, 'dist', 'index.html'); // Corrected path
    console.log(`Loading frontend from built file: ${indexPath}`);
    if (!fs.existsSync(indexPath)) {
      console.error(`Frontend build (index.html) not found at: ${indexPath}`);
      dialog.showErrorBox(
        'Frontend Error',
        `The frontend application file (index.html) was not found at the expected location: ${indexPath}. The application cannot start. Please ensure the frontend has been built correctly.`
      );
      app.quit();
      return;
    }
    mainWindow.loadFile(indexPath);
    // (Unuse) Temporarily open DevTools in production build for debugging
    // mainWindow.webContents.openDevTools();
  }
  console.log('Main window created and content loaded/loading.');
}

function startBackend() {
  console.log('Attempting to start backend...');
  if (!checkJava()) {
    console.log('Java check failed. Aborting backend start and quitting app.');
    app.quit();
    return;
  }

  const jarPathInDev = path.join(__dirname, '..', '..', 'target', jarName);
  const jarPathInProd = app.isPackaged ?
    path.join(process.resourcesPath, 'backend', jarName) : // Removed 'app.asar.unpacked'
    jarPathInDev;

  const finalJarPath = app.isPackaged ? jarPathInProd : jarPathInDev;
  console.log(`Resolved backend JAR path: ${finalJarPath}`);

  if (!fs.existsSync(finalJarPath)) {
    console.error(`Backend JAR not found at: ${finalJarPath}`);
    dialog.showErrorBox(
      'Backend Error',
      `The backend application file (JAR) was not found at the expected location: ${finalJarPath}. The application cannot start. Ensure the JAR is correctly included in the package.`
    );
    app.quit();
    return;
  }

  const backendArgs = [
    '-jar',
    finalJarPath,
    `--server.port=${backendPort}`,
    `--spring.datasource.url=jdbc:sqlite:${path.join(app.getPath('userData'), 'couchat_app_data.db')}`,
    `-Dlogging.file.path=${app.getPath('userData')}` // Add system property for log file path
  ];
  console.log(`Spawning backend process: java ${backendArgs.join(' ')}`);

  const options = {
    cwd: path.dirname(finalJarPath), // Set working directory to the JAR's directory
    detached: false // Keep it false unless you have specific reasons for detaching
  };

  backendProcess = spawn('java', backendArgs, options);

  backendProcess.stdout.on('data', (data) => {
    console.log(`Backend stdout: ${data.toString().trim()}`);
  });

  backendProcess.stderr.on('data', (data) => {
    console.error(`Backend stderr: ${data.toString().trim()}`);
  });

  backendProcess.on('close', (code) => {
    console.log(`Backend process exited with code ${code}`);
    backendProcess = null;
    if (app.isQuitting) return;

    if (code !== 0 && code !== null) {
      dialog.showErrorBox(
        'Backend Stopped Unexpectedly',
        `The backend service stopped unexpectedly with exit code: ${code}. Please check the logs for more details (you might find logs in the application's user data directory).`
      );
    }
  });

  backendProcess.on('error', (err) => {
    console.error('Failed to start backend process:', err);
    dialog.showErrorBox(
      'Backend Startup Error',
      `Failed to start the backend service: ${err.message}. Ensure Java is correctly installed and the application files are intact.`
    );
    backendProcess = null;
    if (!app.isQuitting) {
      app.quit();
    }
  });
  console.log('Backend process spawn initiated.');
}

// Ensure app.isQuitting is defined
app.isQuitting = false;

app.whenReady().then(() => {
  console.log('App is ready.');
  console.log('User data path:', app.getPath('userData')); // Log user data path
  startBackend();
  createWindow();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  console.log('All windows closed.');
  if (process.platform !== 'darwin') {
    console.log('Quitting app (not macOS).');
    app.quit();
  }
});

app.on('will-quit', (event) => {
  console.log('App will-quit event triggered.');
  app.isQuitting = true;
  if (backendProcess) {
    console.log('Attempting to kill backend process...');
    const killed = backendProcess.kill('SIGTERM');
    console.log(`Backend process SIGTERM signal sent: ${killed}`);
  } else {
    console.log('No backend process to kill or already terminated.');
  }
});
