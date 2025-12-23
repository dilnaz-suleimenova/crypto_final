# Secure Auth Backend (Node.js)

Это переписанный backend на Node.js/Express для твоего проекта Secure Auth.

## Установка

```bash
cd backend-node
npm install
npm start
```

Сервер поднимется на:

- http://localhost:8000

Фронтенд (React) уже настроен работать с этим backend по адресам `/api/...`:
- POST /api/register
- POST /api/login/start
- POST /api/login/verify
- POST /api/reset/request
- POST /api/reset/confirm
- GET  /api/me

Данные пользователей и токенов хранятся в JSON-файлах в папке `backend-node/data/`.
RSA-ключи для JWT создаются автоматически в `backend-node/keys/`.
```