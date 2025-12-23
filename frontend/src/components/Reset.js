import React, { useState } from 'react';
import { FaEnvelope } from 'react-icons/fa';
import { Link } from 'react-router-dom';
import './Reset.css';
import { apiResetRequest, apiResetConfirm } from '../api';

function Reset() {
  const [emailOrPhone, setEmailOrPhone] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [step, setStep] = useState(1);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleRequest = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    try {
      const data = await apiResetRequest({ emailOrPhone });
      if (data.reset_token) {
        setResetToken(data.reset_token);
        setMessage('Токен сброса создан. В учебных целях он показан ниже.');
        setStep(2);
      } else if (data.message) {
        setMessage(data.message);
      }
    } catch (err) {
      setError(err.message || 'Ошибка запроса сброса пароля');
    }
  };

  const handleConfirm = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    try {
      const data = await apiResetConfirm({ token: resetToken, new_password: newPassword });
      setMessage(data.message || 'Пароль успешно изменён');
    } catch (err) {
      setError(err.message || 'Ошибка подтверждения сброса');
    }
  };

  return (
    <div className="reset-container">
      <h2>Восстановление пароля</h2>
      <p className="subtitle">Запросите токен и установите новый пароль</p>

      {step === 1 && (
        <form onSubmit={handleRequest}>
          <div className="input-group">
            <label>Email или телефон</label>
            <div className="input-with-icon">
              <FaEnvelope className="input-icon" />
              <input
                type="text"
                value={emailOrPhone}
                onChange={(e) => setEmailOrPhone(e.target.value)}
                required
              />
            </div>
          </div>

          {error && <div className="error-text">{error}</div>}
          {message && <div className="info-text">{message}</div>}

          <button type="submit" className="reset-button">Отправить запрос</button>
        </form>
      )}

      {step === 2 && (
        <form onSubmit={handleConfirm}>
          <div className="input-group">
            <label>Токен сброса (hex)</label>
            <input
              type="text"
              value={resetToken}
              onChange={(e) => setResetToken(e.target.value)}
              required
            />
          </div>

          <div className="input-group">
            <label>Новый пароль</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </div>

          {error && <div className="error-text">{error}</div>}
          {message && <div className="info-text">{message}</div>}

          <button type="submit" className="reset-button">Подтвердить</button>
        </form>
      )}

      <p className="back-link">
        <Link to="/login">← Назад к входу</Link>
      </p>

      {resetToken && (
        <div className="token-box">
          <strong>Учебный reset token:</strong> {resetToken}
        </div>
      )}
    </div>
  );
}

export default Reset;
