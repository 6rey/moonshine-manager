import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Trash2, Layers } from 'lucide-react';
import Modal from '../components/Modal';

const Groups = () => {
  const [groups, setGroups] = useState([]);
  const [isModalOpen, setModalOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const navigate = useNavigate();

  const fetchGroups = async () => {
    try {
      const res = await fetch('/api/groups', { credentials: 'include' });
      if (res.status === 401 || res.status === 403) return navigate('/login');
      const data = await res.json();
      setGroups(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchGroups();
  }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!newGroupName.trim()) return;
    
    await fetch('/api/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ name: newGroupName })
    });
    setNewGroupName('');
    setModalOpen(false);
    fetchGroups();
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Вы уверены?')) return;
    await fetch(`/api/groups/${id}`, {
      method: 'DELETE',
      credentials: 'include'
    });
    fetchGroups();
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white">Группы (Pools)</h2>
        <button 
          onClick={() => setModalOpen(true)}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-xl transition-all shadow-lg shadow-blue-600/20"
        >
          <Plus className="w-5 h-5" />
          Добавить группу
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {groups.map(group => (
          <div key={group.id} className="bg-gray-900 border border-gray-800 p-6 rounded-2xl flex items-center justify-between group hover:border-gray-700 transition-colors">
            <div className="flex items-center gap-4">
              <div className="bg-blue-500/10 p-3 rounded-xl">
                <Layers className="w-6 h-6 text-blue-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-200">{group.name}</h3>
            </div>
            <button 
              onClick={() => handleDelete(group.id)}
              className="text-gray-500 hover:text-red-400 p-2 rounded-lg hover:bg-red-500/10 transition-colors opacity-0 group-hover:opacity-100"
            >
              <Trash2 className="w-5 h-5" />
            </button>
          </div>
        ))}
        {groups.length === 0 && (
          <div className="col-span-full p-8 text-center text-gray-500 border border-dashed border-gray-700 rounded-2xl">
            Пока нет созданных групп.
          </div>
        )}
      </div>

      <Modal isOpen={isModalOpen} onClose={() => setModalOpen(false)} title="Создать новую группу">
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Название группы</label>
            <input 
              type="text" 
              value={newGroupName}
              onChange={(e) => setNewGroupName(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 text-white rounded-xl p-3 focus:ring-2 focus:ring-blue-500 outline-none transition-all"
              placeholder="Например: Разработчики"
              autoFocus
            />
          </div>
          <button 
            type="submit"
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 rounded-xl transition-all"
          >
            Сохранить
          </button>
        </form>
      </Modal>
    </div>
  );
};

export default Groups;
