// main.js - Основной процесс Electron
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const axios = require('axios');
// require('dotenv').config(); // загружаем .env
const jwt = require('jsonwebtoken');
const https = require('https');
const { spawn } = require('child_process');
const { promisify } = require('util');

// Moonlight configuration
const MOONLIGHT_EXEC = 'C:/moonlight/Moonlight.exe';
const agent = new https.Agent({ rejectUnauthorized: false });

const axiosInstance = axios.create({
  baseURL: 'https://192.168.116.11',   // URL‑сервера
  timeout: 10000,
  httpsAgent: agent,               // <-- отключаем проверку
});

module.exports = { axiosInstance };  // используйте позже вместо простого axios

// Конфигурация API
const API_CONFIG = {
  BASE_URL: process.env.VUE_APP_API_URL || 'https://192.168.116.11',
  LOGIN_PATH: '/auth/token',
  USERS_PATH: '/admin/users',
  VMS_PATH: '/vm/list',
  ASSIGNMENTS_PATH: '/vm/assignments',
  ASSIGN_PATH: '/vm/assign',
  UNASSIGN_PATH: '/vm/unassign',
  PREPARE_PAIRING_PATH: '/vm/prepare-pairing',
  COMPLETE_PAIRING_PATH: '/vm/complete-pairing'
};

let mainWindow;
let token = null;
let currentUser = null;
let userRole = null;

// Функция для создания окна приложения
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadFile('renderer.html');

  // Открыть DevTools в режиме разработки
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }
}

// Функция для отправки логов в renderer process
function sendLog(level, message, data = null) {
  const timestamp = new Date().toLocaleTimeString();
  const logEntry = {
    timestamp,
    level, // 'info', 'success', 'error', 'warning'
    message,
    data
  };

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('log-message', logEntry);
  }

  // Also log to console
  console.log(`[${timestamp}] [${level.toUpperCase()}] ${message}`, data || '');
}

// Функция для выполнения API запросов
async function fetchAPI(endpoint, options = {}) {
  const url = `${API_CONFIG.BASE_URL}${endpoint}`;

  sendLog('info', `API Request: ${options.method || 'GET'} ${endpoint}`);

  try {
    // здесь используем уже созданный экземпляр
    const response = await axiosInstance({
      url,
      ...options,
      headers: {
        ...options.headers,
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      }
    });

    sendLog('success', `API Response: ${options.method || 'GET'} ${endpoint} - Status ${response.status}`);
    return response.data;
  } catch (error) {
    const errorMsg = error.response?.data?.detail || error.message;
    sendLog('error', `API Error: ${options.method || 'GET'} ${endpoint}`, errorMsg);
    console.error('API Error:', error.response?.data || error.message);
    throw error;
  }
}

// Обработчики IPC событий
ipcMain.handle('login', async (event, { username, password }) => {
  try {
    sendLog('info', `Login attempt for user: ${username}`);
    const data = await fetchAPI(API_CONFIG.LOGIN_PATH, {
      method: 'POST',
      data: { username, password }
    });

    token = data.access_token;

    // Декодируем токен для получения информации о пользователе
    const decoded = jwt.decode(token);
    currentUser = decoded.sub;
    userRole = decoded.role;

    sendLog('success', `User ${currentUser} logged in successfully (Role: ${userRole})`);
    return { success: true, token, user: currentUser, role: userRole };
  } catch (error) {
    sendLog('error', `Login failed for user: ${username}`, error.response?.data?.detail);
    return { success: false, error: error.response?.data?.detail || 'Authentication failed' };
  }
});

ipcMain.handle('get-users', async () => {
  try {
    const users = await fetchAPI(API_CONFIG.USERS_PATH, { method: 'GET' });
    return { success: true, users };
  } catch (error) {
    return { success: false, error: error.response?.data?.detail || 'Failed to load users' };
  }
});

ipcMain.handle('get-vms', async () => {
  try {
    const vms = await fetchAPI(API_CONFIG.VMS_PATH, { method: 'GET' });
    return { success: true, vms };
  } catch (error) {
    return { success: false, error: error.response?.data?.detail || 'Failed to load VMs' };
  }
});

ipcMain.handle('get-assignments', async () => {
  try {
    const assignments = await fetchAPI(API_CONFIG.ASSIGNMENTS_PATH, { method: 'GET' });
    return { success: true, assignments };
  } catch (error) {
    return { success: false, error: error.response?.data?.detail || 'Failed to load assignments' };
  }
});

ipcMain.handle('create-user', async (event, userData) => {
  try {
    const user = await fetchAPI('/auth/register', {
      method: 'POST',
      data: userData
    });
    return { success: true, user };
  } catch (error) {
    return { success: false, error: error.response?.data?.detail || 'Failed to create user' };
  }
});

ipcMain.handle('delete-user', async (event, userId) => {
  try {
    await fetchAPI(`/admin/user/${userId}`, { method: 'DELETE' });
    return { success: true };
  } catch (error) {
    return { success: false, error: error.response?.data?.detail || 'Failed to delete user' };
  }
});

ipcMain.handle('assign-vm', async (event, assignmentData) => {
  try {
    await fetchAPI(API_CONFIG.ASSIGN_PATH, {
      method: 'POST',
      data: assignmentData
    });
    return { success: true };
  } catch (error) {
    return { success: false, error: error.response?.data?.detail || 'Failed to assign VM' };
  }
});

ipcMain.handle('unassign-vm', async (event, unassignData) => {
  try {
    await fetchAPI(API_CONFIG.UNASSIGN_PATH, {
      method: 'DELETE',
      data: unassignData
    });
    return { success: true };
  } catch (error) {
    return { success: false, error: error.response?.data?.detail || 'Failed to unassign VM' };
  }
});

ipcMain.handle('prepare-pairing', async (event, vmId) => {
  try {
    const data = await fetchAPI(API_CONFIG.PREPARE_PAIRING_PATH, {
      method: 'POST',
      data: { vm_id: vmId }
    });
    return { success: true, ...data };
  } catch (error) {
    return { success: false, error: error.response?.data?.detail || 'Failed to prepare pairing' };
  }
});

ipcMain.handle('complete-pairing', async (event, pairingData) => {
  try {
    const data = await fetchAPI(API_CONFIG.COMPLETE_PAIRING_PATH, {
      method: 'POST',
      data: pairingData
    });
    return { success: true, ...data };
  } catch (error) {
    return { success: false, error: error.response?.data?.detail || 'Failed to complete pairing' };
  }
});

// Helper function to check if pairing exists
async function checkPairingStatus(ip) {
  return new Promise((resolve) => {
    sendLog('info', `Checking pairing status with ${ip}...`);

    const checkProcess = spawn(MOONLIGHT_EXEC, ['list', ip]);
    let output = '';
    let errorOutput = '';

    checkProcess.stdout.on('data', (data) => {
      output += data.toString();
    });

    checkProcess.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    checkProcess.on('close', (code) => {
      if (code === 0) {
        sendLog('success', 'Pairing already exists - skipping pairing process');
        resolve(true);
      } else {
        sendLog('info', 'No existing pairing found - pairing required');
        resolve(false);
      }
    });

    checkProcess.on('error', (err) => {
      sendLog('warning', `Error checking pairing status: ${err.message}`);
      resolve(false);
    });

    // Timeout after 10 seconds
    setTimeout(() => {
      checkProcess.kill();
      sendLog('warning', 'Pairing check timed out - assuming pairing required');
      resolve(false);
    }, 10000);
  });
}

// Helper function to run Moonlight command
function runMoonlightCommand(args) {
  return new Promise((resolve, reject) => {
    const cmdString = `${MOONLIGHT_EXEC} ${args.join(' ')}`;
    sendLog('info', `Running command: ${cmdString}`);

    const process = spawn(MOONLIGHT_EXEC, args);
    let output = '';
    let errorOutput = '';

    process.stdout.on('data', (data) => {
      output += data.toString();
    });

    process.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    process.on('close', (code) => {
      if (code === 0) {
        sendLog('success', `Command completed successfully`);
        resolve({ success: true, code, output });
      } else {
        sendLog('error', `Command failed with code ${code}`, errorOutput);
        reject({ success: false, code, error: errorOutput });
      }
    });

    process.on('error', (err) => {
      sendLog('error', `Failed to start Moonlight: ${err.message}`);
      reject({ success: false, error: err.message });
    });
  });
}

// Main connect to VM handler
ipcMain.handle('connect-to-vm', async (event, vmId) => {
  try {
    sendLog('info', `Connecting to VM ${vmId}...`);

    // Get VM information
    const vms = await fetchAPI(API_CONFIG.VMS_PATH, { method: 'GET' });
    const vm = vms.find(v => v.id === parseInt(vmId));

    if (!vm) {
      sendLog('error', `VM ${vmId} not found`);
      return { success: false, error: 'VM not found' };
    }

    const ip = vm.ip_address;
    sendLog('info', `VM IP: ${ip}, Hostname: ${vm.hostname}`);

    // Check if pairing exists
    const pairingExists = await checkPairingStatus(ip);

    // Only perform pairing if it doesn't exist
    if (!pairingExists) {
      sendLog('info', 'Starting pairing process...');

      // Prepare pairing - get PIN from server
      const pairingData = await fetchAPI(API_CONFIG.PREPARE_PAIRING_PATH, {
        method: 'POST',
        data: { vm_id: parseInt(vmId) }
      });

      const pin = pairingData.pin;
      if (!pin) {
        sendLog('error', 'PIN not received from server');
        return { success: false, error: 'No PIN received' };
      }

      sendLog('success', `PIN received: ${pin}`);

      // Launch Moonlight for pairing
      sendLog('info', 'Launching Moonlight for pairing...');
      const pairProcess = spawn(MOONLIGHT_EXEC, ['pair', ip, '-pin', pin]);

      // Wait a bit for Moonlight to start
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Send PIN to Sunshine via server
      sendLog('info', 'Sending PIN to Sunshine...');
      try {
        await fetchAPI(API_CONFIG.COMPLETE_PAIRING_PATH, {
          method: 'POST',
          data: { vm_id: parseInt(vmId), pin: pin }
        });
      } catch (error) {
        sendLog('error', 'Failed to complete pairing on server');
        pairProcess.kill();
        return { success: false, error: 'Pairing failed' };
      }

      // Wait for pairing process to complete
      const pairResult = await new Promise((resolve) => {
        pairProcess.on('close', (code) => {
          if (code === 0) {
            sendLog('success', 'Pairing completed successfully!');
            resolve({ success: true });
          } else {
            sendLog('error', `Moonlight pairing failed with code ${code}`);
            resolve({ success: false, error: `Pairing failed: ${code}` });
          }
        });

        pairProcess.on('error', (err) => {
          sendLog('error', `Pairing error: ${err.message}`);
          resolve({ success: false, error: err.message });
        });
      });

      if (!pairResult.success) {
        return pairResult;
      }
    }

    // Launch streaming
    sendLog('info', 'Starting streaming...');
    const streamArgs = ['stream', ip, 'Desktop', '--resolution', '1920x1080', '--fps', '60'];

    try {
      await runMoonlightCommand(streamArgs);
      sendLog('success', 'Streaming session ended');
      return { success: true, message: 'Streaming completed' };
    } catch (error) {
      sendLog('error', 'Streaming failed', error.error);
      return { success: false, error: 'Streaming failed' };
    }

  } catch (error) {
    sendLog('error', `Error during connection: ${error.message}`);
    return { success: false, error: error.message || 'Connection failed' };
  }
});

// Жизненный цикл приложения
app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
