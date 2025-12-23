
const API_BASE = "http://localhost:8000/api";

export async function apiRegister({ method, emailOrPhone, password }) {
  const res = await fetch(`${API_BASE}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ method, emailOrPhone, password }),
  });
  if (!res.ok) {
    let msg = "Ошибка регистрации";
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

export async function apiLoginStart({ method, emailOrPhone, password }) {
  const res = await fetch(`${API_BASE}/login/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ method, emailOrPhone, password }),
  });
  if (!res.ok) {
    let msg = "Ошибка входа";
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }
  return res.json(); // { challenge_token }
}

export async function apiLoginVerify({ challenge_token, totp_code }) {
  const res = await fetch(`${API_BASE}/login/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge_token, totp_code }),
  });
  if (!res.ok) {
    let msg = "Ошибка MFA кода";
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }
  return res.json(); // { access_token, token_type }
}

export async function apiResetRequest({ emailOrPhone }) {
  const res = await fetch(`${API_BASE}/reset/request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ emailOrPhone }),
  });
  if (!res.ok) {
    let msg = "Ошибка запроса сброса пароля";
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }
  return res.json(); // { reset_token? or message }
}

export async function apiResetConfirm({ token, new_password }) {
  const res = await fetch(`${API_BASE}/reset/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, new_password }),
  });
  if (!res.ok) {
    let msg = "Ошибка подтверждения сброса пароля";
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

export async function apiGetMe() {
  const access_token = localStorage.getItem("access_token");
  if (!access_token) throw new Error("Нет access_token, войдите заново");

  const res = await fetch(`${API_BASE}/me`, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  if (!res.ok) {
    let msg = "Ошибка получения профиля";
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}
