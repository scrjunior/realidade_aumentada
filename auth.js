// ═══════════════════════════════════════════════════════
//  AUTH MODULE — Plantas AR
//  Armazenamento: localStorage (migrar para DB depois)
//  Chave de utilizadores: 'plantas_ar_users'
//  Chave de sessão ativa: 'plantas_ar_session'
// ═══════════════════════════════════════════════════════

const Auth = (() => {
  const USERS_KEY   = 'plantas_ar_users';
  const SESSION_KEY = 'plantas_ar_session';

  // ── Helpers de persistência
  function getUsers() {
    try { return JSON.parse(localStorage.getItem(USERS_KEY)) || []; }
    catch { return []; }
  }
  function saveUsers(users) {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
  }

  // ── Hash simples (não criptográfico — substituir por bcrypt no backend)
  async function hashPassword(password) {
    const buf = await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode(password + 'plantas_ar_salt_2024')
    );
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── Validações
  function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  }
  function validatePassword(password) {
    if (password.length < 6) return 'A senha deve ter pelo menos 6 caracteres.';
    return null;
  }
  function validateName(name) {
    if (!name || name.trim().length < 2) return 'O nome deve ter pelo menos 2 caracteres.';
    return null;
  }

  // ── Registo
  async function register({ name, email, password, confirmPassword }) {
    const nameErr = validateName(name);
    if (nameErr) return { ok: false, error: nameErr };

    if (!validateEmail(email)) return { ok: false, error: 'Email inválido.' };

    const passErr = validatePassword(password);
    if (passErr) return { ok: false, error: passErr };

    if (password !== confirmPassword) return { ok: false, error: 'As senhas não coincidem.' };

    const users = getUsers();
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      return { ok: false, error: 'Este email já está registado.' };
    }

    const hash = await hashPassword(password);
    const newUser = {
      id: crypto.randomUUID(),
      name: name.trim(),
      email: email.trim().toLowerCase(),
      passwordHash: hash,
      createdAt: new Date().toISOString(),
      projectsCount: 0,
    };

    users.push(newUser);
    saveUsers(users);

    // Iniciar sessão automaticamente após registo
    const session = { userId: newUser.id, name: newUser.name, email: newUser.email, loginAt: new Date().toISOString() };
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));

    return { ok: true, user: { id: newUser.id, name: newUser.name, email: newUser.email } };
  }

  // ── Login
  async function login({ email, password }) {
    if (!validateEmail(email)) return { ok: false, error: 'Email inválido.' };
    if (!password) return { ok: false, error: 'Introduz a senha.' };

    const users = getUsers();
    const user = users.find(u => u.email === email.trim().toLowerCase());
    if (!user) return { ok: false, error: 'Email ou senha incorretos.' };

    const hash = await hashPassword(password);
    if (hash !== user.passwordHash) return { ok: false, error: 'Email ou senha incorretos.' };

    const session = { userId: user.id, name: user.name, email: user.email, loginAt: new Date().toISOString() };
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));

    return { ok: true, user: { id: user.id, name: user.name, email: user.email } };
  }

  // ── Logout
  function logout() {
    localStorage.removeItem(SESSION_KEY);
  }

  // ── Sessão atual
  function getSession() {
    try { return JSON.parse(localStorage.getItem(SESSION_KEY)); }
    catch { return null; }
  }

  function isLoggedIn() {
    return !!getSession();
  }

  return { register, login, logout, getSession, isLoggedIn };
})();

// Exportar para uso no main (se usado como módulo)
if (typeof module !== 'undefined') module.exports = Auth;