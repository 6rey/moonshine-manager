// renderer.js - Логика рендерер-процесса
let currentUser = null;
let userRole = null;
let usersList = [];
let vmsList = [];
let assignmentsList = [];

// DOM элементы
const loginForm = document.getElementById('loginForm');
const content = document.getElementById('content');
const loginButton = document.getElementById('loginButton');
const logoutButton = document.getElementById('logoutButton');
const currentUserSpan = document.getElementById('currentUser');

// Функция для отображения сообщений
function showMessage(elementId, message, isSuccess = true) {
  const element = document.getElementById(elementId);
  element.textContent = message;
  element.className = `status-message ${isSuccess ? 'status-success' : 'status-error'}`;
  element.classList.remove('hidden');

  // Скрыть сообщение через 5 секунд
  setTimeout(() => {
    element.classList.add('hidden');
  }, 5000);
}

// Функция для очистки сообщений
function clearMessage(elementId) {
  const element = document.getElementById(elementId);
  element.classList.add('hidden');
}

// Функция для переключения вкладок
function setupTabs() {
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Убрать активный класс у всех вкладок и содержимого
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(tc => tc.classList.remove('active'));

      // Добавить активный класс к выбранной вкладке
      tab.classList.add('active');
      const tabId = tab.getAttribute('data-tab');
      document.getElementById(`${tabId}-content`).classList.add('active');
    });
  });
}

// Функция для входа
async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  if (!username || !password) {
    showMessage('loginMessage', 'Пожалуйста, заполните все поля', false);
    return;
  }

  try {
    loginButton.disabled = true;
    loginButton.textContent = 'Вход...';

    const result = await window.electronAPI.login({ username, password });

    if (result.success) {
      currentUser = result.user;
      userRole = result.role;

      // Показать основной интерфейс
      loginForm.style.display = 'none';
      content.style.display = 'block';

      // Обновить информацию о пользователе
      currentUserSpan.textContent = `Вы вошли как: ${currentUser} (${userRole})`;

      // Загрузить данные
      await loadAllData();

      // Показать соответствующие вкладки в зависимости от роли
      if (userRole === 'admin' || userRole === 'master') {
        document.querySelector('[data-tab="admin-users"]').style.display = 'block';
        document.querySelector('[data-tab="admin-vms"]').style.display = 'block';
        document.querySelector('[data-tab="admin-assignments"]').style.display = 'block';
      } else {
        document.querySelector('[data-tab="admin-users"]').style.display = 'none';
        document.querySelector('[data-tab="admin-vms"]').style.display = 'none';
        document.querySelector('[data-tab="admin-assignments"]').style.display = 'none';
      }

      showMessage('loginMessage', 'Вход выполнен успешно', true);
    } else {
      showMessage('loginMessage', result.error, false);
    }
  } catch (error) {
    showMessage('loginMessage', 'Ошибка подключения к серверу', false);
  } finally {
    loginButton.disabled = false;
    loginButton.textContent = 'Войти';
  }
}

// Функция для выхода
function logout() {
  // Скрыть основной интерфейс и показать форму входа
  content.style.display = 'none';
  loginForm.style.display = 'block';

  // Очистить поля формы
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';

  // Сбросить данные
  currentUser = null;
  userRole = null;
  usersList = [];
  vmsList = [];
  assignmentsList = [];

  // Очистить таблицы
  document.querySelector('#usersTable tbody').innerHTML = '';
  document.querySelector('#vmsTable tbody').innerHTML = '';
  document.querySelector('#assignmentsTable tbody').innerHTML = '';
  document.querySelector('#userVMsTable tbody').innerHTML = '';

  clearMessage('loginMessage');
}

// Функция для загрузки всех данных
async function loadAllData() {
  await loadUsers();
  await loadVMs();
  await loadAssignments();
  await loadUserVMs();
}

// Функция для загрузки пользователей
async function loadUsers() {
  if (userRole !== 'admin' && userRole !== 'master') return;

  try {
    const result = await window.electronAPI.getUsers();

    if (result.success) {
      usersList = result.users;

      // Обновить таблицу пользователей
      const tbody = document.querySelector('#usersTable tbody');
      tbody.innerHTML = '';

      result.users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>${user.id}</td>
          <td>${user.username}</td>
          <td>${user.role}</td>
          <td>
            <button class="btn btn-danger delete-user-btn" data-user-id="${user.id}">Удалить</button>
          </td>
        `;
        tbody.appendChild(row);
      });

      // Добавить обработчики событий для кнопок удаления
      document.querySelectorAll('.delete-user-btn').forEach(button => {
        button.addEventListener('click', async (e) => {
          const userId = e.target.getAttribute('data-user-id');
          await deleteUser(userId);
        });
      });

      // Обновить выпадающий список пользователей для назначений
      updateAssignUsersDropdown();

      showMessage('usersListMessage', 'Список пользователей обновлен', true);
    } else {
      showMessage('usersListMessage', result.error, false);
    }
  } catch (error) {
    showMessage('usersListMessage', 'Ошибка загрузки пользователей', false);
  }
}

// Функция для создания пользователя
async function createUser() {
  const username = document.getElementById('newUsername').value;
  const password = document.getElementById('newPassword').value;
  const role = document.getElementById('newRole').value;

  if (!username || !password) {
    showMessage('createUserMessage', 'Пожалуйста, заполните все поля', false);
    return;
  }

  try {
    const result = await window.electronAPI.createUser({ username, password, role });

    if (result.success) {
      showMessage('createUserMessage', 'Пользователь успешно создан', true);
      document.getElementById('newUsername').value = '';
      document.getElementById('newPassword').value = '';

      // Обновить список пользователей
      await loadUsers();
    } else {
      showMessage('createUserMessage', result.error, false);
    }
  } catch (error) {
    showMessage('createUserMessage', 'Ошибка создания пользователя', false);
  }
}

// Функция для удаления пользователя
async function deleteUser(userId) {
  if (!confirm('Вы уверены, что хотите удалить этого пользователя?')) {
    return;
  }

  try {
    const result = await window.electronAPI.deleteUser(userId);

    if (result.success) {
      showMessage('usersListMessage', 'Пользователь успешно удален', true);
      await loadUsers();
    } else {
      showMessage('usersListMessage', result.error, false);
    }
  } catch (error) {
    showMessage('usersListMessage', 'Ошибка удаления пользователя', false);
  }
}

// Функция для загрузки виртуальных машин
async function loadVMs() {
  try {
    const result = await window.electronAPI.getVMs();

    if (result.success) {
      vmsList = result.vms;

      // Обновить таблицу виртуальных машин для администратора
      if (userRole === 'admin' || userRole === 'master') {
        const tbody = document.querySelector('#vmsTable tbody');
        tbody.innerHTML = '';

        result.vms.forEach(vm => {
          const row = document.createElement('tr');
          row.innerHTML = `
            <td>${vm.id}</td>
            <td>${vm.hostname}</td>
            <td>${vm.ip_address}</td>
            <td>${vm.sunshine_user}</td>
          `;
          tbody.appendChild(row);
        });
      }

      // Обновить выпадающий список виртуальных машин для назначений
      updateAssignVMsDropdown();

      showMessage('vmsListMessage', 'Список виртуальных машин обновлен', true);
    } else {
      showMessage('vmsListMessage', result.error, false);
    }
  } catch (error) {
    showMessage('vmsListMessage', 'Ошибка загрузки виртуальных машин', false);
  }
}

// Функция для загрузки назначений
async function loadAssignments() {
  if (userRole !== 'admin' && userRole !== 'master') return;

  try {
    const result = await window.electronAPI.getAssignments();

    if (result.success) {
      assignmentsList = result.assignments;

      // Обновить таблицу назначений
      const tbody = document.querySelector('#assignmentsTable tbody');
      tbody.innerHTML = '';

      result.assignments.forEach(assignment => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>${assignment.id}</td>
          <td>${assignment.username}</td>
          <td>${assignment.vm_hostname}</td>
          <td>
            <button class="btn btn-danger unassign-btn" data-user-id="${assignment.user_id}" data-vm-id="${assignment.vm_id}">Отменить назначение</button>
          </td>
        `;
        tbody.appendChild(row);
      });

      // Добавить обработчики событий для кнопок отмены назначения
      document.querySelectorAll('.unassign-btn').forEach(button => {
        button.addEventListener('click', async (e) => {
          const userId = e.target.getAttribute('data-user-id');
          const vmId = e.target.getAttribute('data-vm-id');
          await unassignVM(userId, vmId);
        });
      });

      showMessage('assignmentsListMessage', 'Список назначений обновлен', true);
    } else {
      showMessage('assignmentsListMessage', result.error, false);
    }
  } catch (error) {
    showMessage('assignmentsListMessage', 'Ошибка загрузки назначений', false);
  }
}

// Функция для назначения виртуальной машины пользователю
async function assignVM() {
  const userId = document.getElementById('assignUser').value;
  const vmId = document.getElementById('assignVM').value;

  if (!userId || !vmId) {
    showMessage('assignMessage', 'Пожалуйста, выберите пользователя и виртуальную машину', false);
    return;
  }

  try {
    const result = await window.electronAPI.assignVM({ user_id: parseInt(userId), vm_id: parseInt(vmId) });

    if (result.success) {
      showMessage('assignMessage', 'Виртуальная машина успешно назначена', true);

      // Обновить список назначений
      await loadAssignments();
    } else {
      showMessage('assignMessage', result.error, false);
    }
  } catch (error) {
    showMessage('assignMessage', 'Ошибка назначения виртуальной машины', false);
  }
}

// Функция для отмены назначения виртуальной машины
async function unassignVM(userId, vmId) {
  try {
    const result = await window.electronAPI.unassignVM({ user_id: parseInt(userId), vm_id: parseInt(vmId) });

    if (result.success) {
      showMessage('assignmentsListMessage', 'Назначение успешно отменено', true);

      // Обновить список назначений
      await loadAssignments();
    } else {
      showMessage('assignmentsListMessage', result.error, false);
    }
  } catch (error) {
    showMessage('assignmentsListMessage', 'Ошибка отмены назначения', false);
  }
}

// Функция для обновления выпадающего списка пользователей для назначений
function updateAssignUsersDropdown() {
  const select = document.getElementById('assignUser');
  select.innerHTML = '';

  usersList.forEach(user => {
    const option = document.createElement('option');
    option.value = user.id;
    option.textContent = `${user.username} (${user.role})`;
    select.appendChild(option);
  });
}

// Функция для обновления выпадающего списка виртуальных машин для назначений
function updateAssignVMsDropdown() {
  const select = document.getElementById('assignVM');
  select.innerHTML = '';

  vmsList.forEach(vm => {
    const option = document.createElement('option');
    option.value = vm.id;
    option.textContent = `${vm.hostname} (${vm.ip_address})`;
    select.appendChild(option);
  });
}

// Функция для загрузки виртуальных машин пользователя
async function loadUserVMs() {
  try {
    const result = await window.electronAPI.getVMs();

    if (result.success) {
      // Обновить таблицу виртуальных машин пользователя
      const tbody = document.querySelector('#userVMsTable tbody');
      tbody.innerHTML = '';

      result.vms.forEach(vm => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td>${vm.id}</td>
          <td>${vm.hostname}</td>
          <td>${vm.ip_address}</td>
          <td>
            <button class="btn btn-primary connect-vm-btn" data-vm-id="${vm.id}">Подключиться</button>
          </td>
        `;
        tbody.appendChild(row);
      });

      // Добавить обработчики событий для кнопок подключения
      document.querySelectorAll('.connect-vm-btn').forEach(button => {
        button.addEventListener('click', async (e) => {
          const vmId = e.target.getAttribute('data-vm-id');
          await connectToVM(vmId);
        });
      });
    }
  } catch (error) {
    showMessage('userVMsMessage', 'Ошибка загрузки виртуальных машин', false);
  }
}

// Функция для подключения к виртуальной машине
async function connectToVM(vmId) {
  try {
    showMessage('userVMsMessage', 'Подключение к VM... Проверяем статус pairing...', true);

    // Use new comprehensive connection handler
    const result = await window.electronAPI.connectToVM(parseInt(vmId));

    if (result.success) {
      showMessage('userVMsMessage', result.message || 'Подключение успешно установлено и завершено.', true);
    } else {
      showMessage('userVMsMessage', result.error || 'Ошибка подключения', false);
    }
  } catch (error) {
    showMessage('userVMsMessage', 'Ошибка подключения к виртуальной машине', false);
  }
}

// ========== Logging System ==========
// Переменная для отслеживания видимости логов
let logsVisible = true;
const maxLogs = 500; // Максимальное количество логов для хранения

// Функция для добавления лога в панель
function addLog(logEntry) {
  const logContainer = document.getElementById('logContainer');
  const logElement = document.createElement('div');
  logElement.className = `log-entry ${logEntry.level}`;

  const timestamp = document.createElement('span');
  timestamp.className = 'log-timestamp';
  timestamp.textContent = `[${logEntry.timestamp}]`;

  const message = document.createElement('span');
  message.className = 'log-message';
  message.textContent = logEntry.message;

  logElement.appendChild(timestamp);
  logElement.appendChild(message);

  // Добавить дополнительные данные если есть
  if (logEntry.data) {
    const data = document.createElement('span');
    data.className = 'log-data';
    data.textContent = typeof logEntry.data === 'string' ? logEntry.data : JSON.stringify(logEntry.data);
    logElement.appendChild(data);
  }

  logContainer.appendChild(logElement);

  // Ограничить количество логов
  if (logContainer.children.length > maxLogs) {
    logContainer.removeChild(logContainer.firstChild);
  }

  // Автопрокрутка вниз
  logContainer.scrollTop = logContainer.scrollHeight;
}

// Функция для очистки логов
function clearLogs() {
  const logContainer = document.getElementById('logContainer');
  logContainer.innerHTML = '';
  addLog({
    timestamp: new Date().toLocaleTimeString(),
    level: 'info',
    message: 'Logs cleared',
    data: null
  });
}

// Функция для скрытия/показа панели логов
function toggleLogs() {
  const logPanel = document.querySelector('.log-panel');
  const toggleButton = document.getElementById('toggleLogsButton');

  logsVisible = !logsVisible;

  if (logsVisible) {
    logPanel.style.height = '200px';
    toggleButton.textContent = 'Hide';
  } else {
    logPanel.style.height = '30px';
    toggleButton.textContent = 'Show';
  }
}

// Слушатель для получения логов от main process
window.electronAPI.onLogMessage((logEntry) => {
  addLog(logEntry);
});

// Инициализация приложения
document.addEventListener('DOMContentLoaded', () => {
  // Настройка вкладок
  setupTabs();

  // Обработчики событий для формы входа
  loginButton.addEventListener('click', login);

  // Обработчик события для кнопки выхода
  logoutButton.addEventListener('click', logout);

  // Обработчики событий для администраторских функций
  document.getElementById('createUserButton').addEventListener('click', createUser);
  document.getElementById('refreshUsersButton').addEventListener('click', loadUsers);
  document.getElementById('refreshVMsButton').addEventListener('click', loadVMs);
  document.getElementById('refreshAssignmentsButton').addEventListener('click', loadAssignments);
  document.getElementById('assignButton').addEventListener('click', assignVM);

  // Обработчики для панели логов
  document.getElementById('clearLogsButton').addEventListener('click', clearLogs);
  document.getElementById('toggleLogsButton').addEventListener('click', toggleLogs);

  // Скрыть админские вкладки по умолчанию
  document.querySelector('[data-tab="admin-users"]').style.display = 'none';
  document.querySelector('[data-tab="admin-vms"]').style.display = 'none';
  document.querySelector('[data-tab="admin-assignments"]').style.display = 'none';

  // Добавить приветственный лог
  addLog({
    timestamp: new Date().toLocaleTimeString(),
    level: 'info',
    message: 'Eclypse application started - Verbose mode enabled',
    data: null
  });
});
