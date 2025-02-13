document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const login = document.getElementById('login').value;
    const senha = document.getElementById('senha').value;
    const errorDiv = document.getElementById('error');

    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ login, senha })
        });

        const data = await response.json();

        if (response.ok) {
            setToken(data.token);
            window.location.href = data.is_admin ? '/admin.html' : '/profile.html';
        } else {
            errorDiv.textContent = data.mensagem;
            errorDiv.classList.remove('hidden');
        }
    } catch (error) {
        errorDiv.textContent = 'Erro ao conectar com o servidor';
        errorDiv.classList.remove('hidden');
    }
}); 