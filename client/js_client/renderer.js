async function addVM() {
    try {
      const response = await fetch('http://46.37.123.8:5000/api/add_vm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'New_VM' })
      });
  
      const data = await response.json();
      document.getElementById('result').innerText = data.message;
    } catch (error) {
      document.getElementById('result').innerText = 'Ошибка: ' + error.message;
    }
  }