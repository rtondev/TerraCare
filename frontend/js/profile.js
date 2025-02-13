async function loadProfile() {
    const token = checkAuth();
    const errorDiv = document.getElementById('error');
    const adminLink = document.getElementById('admin-link');

    try {
        const response = await fetch(`${API_URL}/me`, {
            headers: {
                'Authorization': token
            }
        });

        if (response.ok) {
            const data = await response.json();
            document.getElementById('nome_completo').textContent = data.nome_completo;
            document.getElementById('cpf').textContent = data.cpf;
            document.getElementById('email').textContent = data.email;
            
            // Mostra link de admin se o usuário for admin
            if (data.is_admin) {
                adminLink.classList.remove('hidden');
            }
        } else {
            logout();
        }
    } catch (error) {
        errorDiv.textContent = 'Erro ao carregar dados do perfil';
        errorDiv.classList.remove('hidden');
    }
}

// Carrega o perfil quando a página é aberta
loadProfile(); 