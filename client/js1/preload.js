// preload.js - Предварительная загрузка для безопасного взаимодействия между процессами
const { contextBridge, ipcRenderer } = require('electron');

// Открываем безопасный API для рендерер-процесса
contextBridge.exposeInMainWorld('electronAPI', {
  // Аутентификация
  login: (credentials) => ipcRenderer.invoke('login', credentials),

  // Пользователи
  getUsers: () => ipcRenderer.invoke('get-users'),
  createUser: (userData) => ipcRenderer.invoke('create-user', userData),
  deleteUser: (userId) => ipcRenderer.invoke('delete-user', userId),

  // Виртуальные машины
  getVMs: () => ipcRenderer.invoke('get-vms'),

  // Назначения
  getAssignments: () => ipcRenderer.invoke('get-assignments'),
  assignVM: (assignmentData) => ipcRenderer.invoke('assign-vm', assignmentData),
  unassignVM: (unassignData) => ipcRenderer.invoke('unassign-vm', unassignData),

  // Паринг
  preparePairing: (vmId) => ipcRenderer.invoke('prepare-pairing', vmId),
  completePairing: (pairingData) => ipcRenderer.invoke('complete-pairing', pairingData),

  // VM Connection with Moonlight
  connectToVM: (vmId) => ipcRenderer.invoke('connect-to-vm', vmId),

  // Логирование
  onLogMessage: (callback) => ipcRenderer.on('log-message', (event, logEntry) => callback(logEntry))
});
