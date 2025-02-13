async function carregarUsuarios() {
    const token = checkAuth();
    const tbody = document.getElementById('usuarios-table');

    try {
        const response = await fetch(`${API_URL}/admin/usuarios`, {
            headers: {
                'Authorization': token
            }
        });

        if (response.ok) {
            const usuarios = await response.json();
            tbody.innerHTML = usuarios.map(usuario => `
                <tr class="border-b">
                    <td class="px-4 py-2">${usuario.nome_completo}</td>
                    <td class="px-4 py-2">${usuario.cpf}</td>
                    <td class="px-4 py-2">${usuario.email}</td>
                    <td class="px-4 py-2">${usuario.is_admin ? 'Sim' : 'Não'}</td>
                    <td class="px-4 py-2">
                        ${!usuario.is_admin ? `
                            <button onclick="deletarUsuario(${usuario.id})" 
                                    class="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600">
                                Deletar
                            </button>
                        ` : ''}
                    </td>
                </tr>
            `).join('');
        } else {
            window.location.href = '/profile.html';
        }
    } catch (error) {
        console.error('Erro ao carregar usuários:', error);
    }
}

async function deletarUsuario(id) {
    if (!confirm('Tem certeza que deseja deletar este usuário?')) return;

    const token = getToken();
    try {
        const response = await fetch(`${API_URL}/admin/usuarios/${id}`, {
            method: 'DELETE',
            headers: {
                'Authorization': token
            }
        });

        if (response.ok) {
            carregarUsuarios();
        } else {
            const data = await response.json();
            alert(data.mensagem);
        }
    } catch (error) {
        console.error('Erro ao deletar usuário:', error);
        alert('Erro ao deletar usuário');
    }
}

// Carrega os usuários quando a página é aberta
carregarUsuarios(); 