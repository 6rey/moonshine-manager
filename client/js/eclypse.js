// eclypse.js
require('dotenv').config(); // Для переменных окружения

const axios = require('axios');

// Функция аутентификации
async function authenticate(username, password) {
  try {
    const response = await axios.post(
      'http://localhost:8000/auth/token', // Убедитесь, что порт правильный
      {
        username,
        password,
      },
      {
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );

    console.log('Токен:', response.data.token);
    return response.data.token;
  } catch (error) {
    console.error('Ошибка аутентификации:', error.message);
    throw error;
  }
}

// Использование
(async () => {
  try {
    const token = await authenticate('ваш_логин', 'ваш_пароль');
    // Далее можно использовать токен для вызова других API
  } catch (err) {
    console.error('Не удалось войти:', err);
  }
})();