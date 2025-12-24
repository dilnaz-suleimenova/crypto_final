import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiLoginStart } from "../api";
import "./Login.css";

function Login() {
  const [method, setMethod] = useState("email");
  const [emailOrPhone, setEmailOrPhone] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");

    try {
      const data = await apiLoginStart({ method, emailOrPhone, password });

      // ВАЖНО: Сохраняем challenge_token
      localStorage.setItem("challenge_token", data.challenge_token);

      // Переход на MFA
      navigate("/mfa");
    } catch (err) {
      setError(err.message || "Ошибка входа");
    }
  };

  return (
    <div className="login-container">
      <h2>Вход</h2>
      <form onSubmit={handleLogin}>
        <label>Тип входа:</label>
        <select value={method} onChange={(e) => setMethod(e.target.value)}>
          <option value="email">Email</option>
          <option value="phone">Телефон</option>
        </select>

        <label>Email или телефон:</label>
        <input
          type="text"
          value={emailOrPhone}
          onChange={(e) => setEmailOrPhone(e.target.value)}
          required
        />

        <label>Пароль:</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        {error && <div className="error-text">{error}</div>}
        <button type="submit" className="login-button">
          Войти
        </button>
        <p>
          Нет аккаунта? <Link to="/register">Регистрация</Link>
        </p>
      </form>
    </div>
  );
}

export default Login;
