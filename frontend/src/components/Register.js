import React, { useState } from 'react';
import { FaEnvelope, FaPhone, FaLock } from 'react-icons/fa';
import { useNavigate, Link } from 'react-router-dom';
import { QRCodeCanvas } from 'qrcode.react';
import './Register.css';
import { apiRegister } from '../api';

function Register() {
  const [method, setMethod] = useState('email');
  const [emailOrPhone, setEmailOrPhone] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [otpAuthUrl, setOtpAuthUrl] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (password !== confirm) {
      setError('Пароли не совпадают!');
      return;
    }

    try {
      const data = await apiRegister({ method, emailOrPhone, password });

      // ВАЖНО: backend возвращает camelCase
      setTotpSecret(data.totpSecret);
      setOtpAuthUrl(data.otpauth_url);

    } catch (err) {
      setError(err.message || 'Ошибка регистрации');
    }
  };

  return (
    <div className="register-container">
      <h2>Регистрация</h2>
      <p className="subtitle">Создайте аккаунт с двухфакторной защитой</p>

      <form onSubmit={handleSubmit}>
        <div className="method-toggle">
          <button
            type="button"
            className={method === 'email' ? 'active' : ''}
            onClick={() => setMethod('email')}
          >
            <FaEnvelope /> Email
          </button>
          <button
            type="button"
            className={method === 'phone' ? 'active' : ''}
            onClick={() => setMethod('phone')}
          >
            <FaPhone /> Телефон
          </button>
        </div>

        <div className="input-group">
          <label>{method === 'email' ? 'Email' : 'Номер телефона'}</label>
          <input
            type={method === 'email' ? 'email' : 'tel'}
            value={emailOrPhone}
            onChange={(e) => setEmailOrPhone(e.target.value)}
            required
          />
        </div>

        <div className="input-group">
          <label>Пароль</label>
          <div className="input-with-icon">
            <FaLock className="input-icon" />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
        </div>

        <div className="input-group">
          <label>Подтверждение пароля</label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
        </div>

        {error && <div className="error-text">{error}</div>}

        {/* QR CODE BLOCK */}
        {otpAuthUrl && (
          <div className="totp-secret-box">
            <p><strong>Отсканируйте QR-код в Google Authenticator</strong></p>

              <QRCodeCanvas value={otpAuthUrl} size={180} />

            <p style={{ marginTop: '10px' }}>
              Или введите вручную:<br />
              <code>{totpSecret}</code>
           </p>
          </div>
        )}


        {!otpAuthUrl && (
          <button type="submit" className="register-button">
            Зарегистрироваться
          </button>
        )}

        <p className="register-link">
          Уже есть аккаунт? <Link to="/login">Войти</Link>
        </p>
      </form>
    </div>
  );
}

export default Register;
