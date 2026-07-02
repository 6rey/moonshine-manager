import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ShieldAlert, User as UserIcon } from 'lucide-react';

const Users = () => {
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const navigate = useNavigate();

  const fetchData = async () => {
    try {
      const [uRes, gRes] = await Promise.all([
        fetch('/api/users', { credentials: 'include' }),
        fetch('/api/groups', { credentials: 'include' })
      ]);
      
      if (uRes.status === 401 || uRes.status === 403) {
        navigate('/login');
        return;
      }
      
      const uData = await uRes.json();
      const gData = await gRes.json();
      setUsers(uData);
      setGroups(gData);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRoleChange = async (userId, newRole) => {
    await fetch(`/api/users/${userId}/role`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ role: newRole })
    });
    fetchData();
  };

  const handleGroupChange = async (userId, newGroupId) => {
    await fetch(`/api/users/${userId}/group`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ group_id: newGroupId === "none" ? null : parseInt(newGroupId) })
    });
    fetchData();
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white">Пользователи</h2>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden shadow-xl">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-800/50 border-b border-gray-800 text-gray-400 text-sm">
              <th className="px-6 py-4 font-medium">Сотрудник (Email)</th>
              <th className="px-6 py-4 font-medium">Роль</th>
              <th className="px-6 py-4 font-medium">Привязка к Группе</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {users.map(user => (
              <tr key={user.id} className="hover:bg-gray-800/20 transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <div className="bg-gray-800 p-2 rounded-lg border border-gray-700">
                      <UserIcon className="w-5 h-5 text-gray-400" />
                    </div>
                    <span className="font-medium text-gray-200">{user.email}</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    {user.role === 'admin' ? (
                      <ShieldAlert className="w-4 h-4 text-red-400" />
                    ) : (
                      <Shield className="w-4 h-4 text-blue-400" />
                    )}
                    <select
                      value={user.role}
                      onChange={(e) => handleRoleChange(user.id, e.target.value)}
                      className={`bg-transparent text-sm font-medium focus:ring-0 focus:outline-none cursor-pointer
                        ${user.role === 'admin' ? 'text-red-400' : 'text-blue-400'}
                      `}
                    >
                      <option value="user" className="text-gray-900">User</option>
                      <option value="admin" className="text-gray-900">Admin</option>
                    </select>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <select
                    value={user.group_id || "none"}
                    onChange={(e) => handleGroupChange(user.id, e.target.value)}
                    className="bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 outline-none transition-colors"
                  >
                    <option value="none">-- Нет группы --</option>
                    {groups.map(g => (
                      <option key={g.id} value={g.id}>{g.name}</option>
                    ))}
                  </select>
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr>
                <td colSpan="3" className="px-6 py-8 text-center text-gray-500">
                  Пользователи не найдены
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Users;
