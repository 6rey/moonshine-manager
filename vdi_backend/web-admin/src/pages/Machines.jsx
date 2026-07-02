import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Trash2, Server, MonitorSmartphone } from 'lucide-react';
import Modal from '../components/Modal';

const Machines = () => {
  const [machines, setMachines] = useState([]);
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  
  const [isModalOpen, setModalOpen] = useState(false);
  const [formData, setFormData] = useState({
    hostname: '',
    type: 'personal', // personal or shared
    bindId: ''
  });
  
  const navigate = useNavigate();

  const fetchData = async () => {
    try {
      const [mRes, uRes, gRes] = await Promise.all([
        fetch('/api/machines', { credentials: 'include' }),
        fetch('/api/users', { credentials: 'include' }),
        fetch('/api/groups', { credentials: 'include' })
      ]);
      
      if (mRes.status === 401 || mRes.status === 403) return navigate('/login');
      
      setMachines(await mRes.json());
      setUsers(await uRes.json());
      setGroups(await gRes.json());
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!formData.hostname.trim()) return;
    
    const res = await fetch('/api/machines', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ hostname: formData.hostname })
    });
    const newMachine = await res.json();
    
    // Step 2: Assign via PUT
    const assignPayload = {
      user_id: formData.type === 'personal' && formData.bindId ? parseInt(formData.bindId) : null,
      group_id: formData.type === 'shared' && formData.bindId ? parseInt(formData.bindId) : null,
    };
    
    if (assignPayload.user_id || assignPayload.group_id) {
        await fetch(`/api/machines/${newMachine.id}/assign`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(assignPayload)
        });
    }
    
    setModalOpen(false);
    setFormData({ hostname: '', type: 'personal', bindId: '' });
    fetchData();
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Удалить этот ПК?')) return;
    await fetch(`/api/machines/${id}`, { method: 'DELETE', credentials: 'include' });
    fetchData();
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white">Рабочие ПК (Хосты)</h2>
        <button 
          onClick={() => setModalOpen(true)}
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-xl transition-all shadow-lg shadow-indigo-600/20"
        >
          <Plus className="w-5 h-5" />
          Добавить ПК
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden shadow-xl">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-800/50 border-b border-gray-800 text-gray-400 text-sm">
              <th className="px-6 py-4 font-medium">ПК (Hostname)</th>
              <th className="px-6 py-4 font-medium">Тип привязки</th>
              <th className="px-6 py-4 font-medium">Владелец</th>
              <th className="px-6 py-4 font-medium text-right">Действия</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {machines.map(machine => (
              <tr key={machine.id} className="hover:bg-gray-800/20 transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <div className="bg-gray-800 p-2 rounded-lg border border-gray-700">
                      <MonitorSmartphone className="w-5 h-5 text-indigo-400" />
                    </div>
                    <span className="font-medium text-gray-200">{machine.hostname}</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  {machine.user_id ? (
                    <span className="bg-purple-500/10 text-purple-400 px-3 py-1 rounded-full text-sm border border-purple-500/20">Personal Desktop</span>
                  ) : machine.group_id ? (
                    <span className="bg-blue-500/10 text-blue-400 px-3 py-1 rounded-full text-sm border border-blue-500/20">Shared Pool</span>
                  ) : (
                    <span className="text-gray-500">Не привязан</span>
                  )}
                </td>
                <td className="px-6 py-4 text-gray-300">
                  {machine.user_id 
                    ? users.find(u => u.id === machine.user_id)?.email || 'Неизвестный юзер'
                    : machine.group_id 
                      ? groups.find(g => g.id === machine.group_id)?.name || 'Неизвестная группа'
                      : '—'
                  }
                </td>
                <td className="px-6 py-4 text-right">
                  <button 
                    onClick={() => handleDelete(machine.id)}
                    className="text-gray-500 hover:text-red-400 p-2 rounded-lg hover:bg-red-500/10 transition-colors"
                  >
                    <Trash2 className="w-5 h-5" />
                  </button>
                </td>
              </tr>
            ))}
            {machines.length === 0 && (
              <tr>
                <td colSpan="4" className="px-6 py-8 text-center text-gray-500">
                  Зарегистрированных ПК пока нет
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal isOpen={isModalOpen} onClose={() => setModalOpen(false)} title="Регистрация нового ПК">
        <form onSubmit={handleCreate} className="space-y-5">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Hostname (Имя компьютера)</label>
            <input 
              type="text" 
              value={formData.hostname}
              onChange={(e) => setFormData({...formData, hostname: e.target.value})}
              className="w-full bg-gray-800 border border-gray-700 text-white rounded-xl p-3 focus:ring-2 focus:ring-indigo-500 outline-none transition-all"
              placeholder="DESKTOP-ABC1234"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-3">Тип привязки (Кто имеет доступ?)</label>
            <div className="grid grid-cols-2 gap-4">
              <label className={`border rounded-xl p-4 cursor-pointer transition-all ${formData.type === 'personal' ? 'border-indigo-500 bg-indigo-500/10' : 'border-gray-700 hover:border-gray-600 bg-gray-800'}`}>
                <input 
                  type="radio" 
                  name="type" 
                  value="personal" 
                  checked={formData.type === 'personal'}
                  onChange={() => setFormData({...formData, type: 'personal', bindId: ''})}
                  className="hidden" 
                />
                <div className="font-medium text-gray-200">Personal</div>
                <div className="text-xs text-gray-500 mt-1">Один сотрудник</div>
              </label>
              
              <label className={`border rounded-xl p-4 cursor-pointer transition-all ${formData.type === 'shared' ? 'border-indigo-500 bg-indigo-500/10' : 'border-gray-700 hover:border-gray-600 bg-gray-800'}`}>
                <input 
                  type="radio" 
                  name="type" 
                  value="shared" 
                  checked={formData.type === 'shared'}
                  onChange={() => setFormData({...formData, type: 'shared', bindId: ''})}
                  className="hidden" 
                />
                <div className="font-medium text-gray-200">Shared Pool</div>
                <div className="text-xs text-gray-500 mt-1">Группа сотрудников</div>
              </label>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">
              {formData.type === 'personal' ? 'Выберите сотрудника' : 'Выберите группу'}
            </label>
            <select
              value={formData.bindId}
              onChange={(e) => setFormData({...formData, bindId: e.target.value})}
              className="w-full bg-gray-800 border border-gray-700 text-white rounded-xl p-3 focus:ring-2 focus:ring-indigo-500 outline-none transition-all"
              required
            >
              <option value="" disabled>-- Сделайте выбор --</option>
              {formData.type === 'personal' 
                ? users.map(u => <option key={u.id} value={u.id}>{u.email}</option>)
                : groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)
              }
            </select>
          </div>

          <button 
            type="submit"
            className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-3 rounded-xl transition-all shadow-lg shadow-indigo-600/30 mt-4"
          >
            Добавить ПК
          </button>
        </form>
      </Modal>
    </div>
  );
};

export default Machines;
