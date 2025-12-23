import React, { useState } from 'react';
import { FaKey } from 'react-icons/fa';
import { useNavigate, Link } from 'react-router-dom';
import './Mfa.css';
import { apiLoginVerify } from '../api';

function Mfa() {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const challenge_token = localStorage.getItem('challenge_token');
    if (!challenge_token) {
      setError('Нет challenge_token. Сначала выполните вход.');
      return;
    }

    try {
      const data = await apiLoginVerify({ challenge_token, totp_code: code });
      localStorage.setItem('access_token', data.access_token);
      localStorage.removeItem('challenge_token');
      alert('Успешный вход! access_token сохранён в localStorage.');
      navigate('/login'); // или на защищённую страницу
    } catch (err) {
      setError(err.message || 'Неверный код');
    }
  };

  return (
    <div className="mfa-container">
      <h2>Подтверждение входа</h2>
      <p className="subtitle">Введите 6-значный код из Google Authenticator</p>

      <form onSubmit={handleSubmit}>
        <div className="input-group">
          <label>Код из приложения</label>
          <div className="input-with-icon">
            <FaKey className="input-icon" />
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              maxLength={6}
              required
            />
          </div>
        </div>

        {error && <div className="error-text">{error}</div>}

        <button type="submit" className="mfa-button">Подтвердить</button>

        <p className="back-link">
          <Link to="/login">← Назад ко входу</Link>
        </p>
      </form>
    </div>
  );
}

export default Mfa;
