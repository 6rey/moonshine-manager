import React from 'react';
import { ShieldAlert } from 'lucide-react';

const Login = () => {
  return (
    <div className="min-h-screen bg-[#0B0F19] flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-gray-900 border border-gray-800 rounded-3xl shadow-2xl p-8 text-center relative overflow-hidden">
        
        {/* Background ambient glow */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-32 bg-blue-600/20 blur-[80px] pointer-events-none" />

        <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 shadow-lg shadow-blue-500/30 mb-8 relative z-10">
          <ShieldAlert className="w-10 h-10 text-white" />
        </div>
        
        <h1 className="text-3xl font-bold text-white mb-3">VDI Admin</h1>
        <p className="text-gray-400 mb-10 text-sm">
          Доступ запрещен. Пожалуйста, авторизуйтесь через корпоративный Google аккаунт для входа в панель управления.
        </p>

        <a
          href="http://127.0.0.1:8000/auth/login/google"
          className="relative inline-flex w-full items-center justify-center px-8 py-4 text-base font-bold text-white transition-all duration-200 bg-blue-600 border border-transparent rounded-xl hover:bg-blue-700 hover:shadow-lg hover:shadow-blue-600/30 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-600 focus:ring-offset-gray-900"
        >
          Войти через Google SSO
        </a>
      </div>
    </div>
  );
};

export default Login;
