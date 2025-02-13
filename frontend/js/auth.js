const API_URL = '';

function getToken() {
    return localStorage.getItem('token');
}

function setToken(token) {
    localStorage.setItem('token', token);
}

function removeToken() {
    localStorage.removeItem('token');
}

function checkAuth() {
    const token = getToken();
    if (!token) {
        window.location.href = '/login.html';
    }
    return token;
}

function logout() {
    removeToken();
    window.location.href = '/login.html';
}

function formatLoginHelp(value) {
    // Verifica se parece com um email
    if (value.includes('@')) {
        return 'Digite seu email completo';
    }
    // Se não for email, assume que é CPF
    return 'Digite seu CPF (apenas números)';
}

// Adicione este código ao final do arquivo
if (document.getElementById('login')) {
    const loginInput = document.getElementById('login');
    loginInput.addEventListener('input', (e) => {
        const helpText = document.getElementById('loginHelp');
        if (helpText) {
            helpText.textContent = formatLoginHelp(e.target.value);
        }
    });
} 