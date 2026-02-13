# Paranoia Server API

Paranoia — сервер безопасного хранения и передачи пользовательских пакетов данных с проверкой подписи и сбором метрик.

---

## Общие требования

- Все запросы выполняются методом **HTTP POST** с телом в формате JSON.  
- Подписи пользователей и администратора — **Ed25519**.  
- Поля, передаваемые в Base64 (`pub_key`, `payload`, `sig`, `admin_sig`), должны быть корректно закодированы и не содержать переносов строки.  
- Все подписи вычисляются от **точной ASCII-конкатенации строк** без разделителей.  
- Числовые поля (`seq`, `after_seq`) сериализуются как десятичные строки без пробелов при формировании подписываемой строки.  
- Сервер возвращает JSON следующего формата:

```json
{
    "success": true|false,
    "message": "описание результата или ошибка"
}
```

- При успешном `/pull` поле `message` содержит массив объектов.  
- Метрики обновляются при каждом запросе.

---

## Генерация ключей

### Admin

```bash
openssl genpkey -algorithm ED25519 -out admin_private.pem
openssl pkey -in admin_private.pem -pubout -outform DER | tail -c 32 | base64 -w0 > admin_public.b64
```

### User

```bash
openssl genpkey -algorithm ED25519 -out user_private.pem
openssl pkey -in user_private.pem -pubout -outform DER | tail -c 32 | base64 -w0 > user_public.b64
```

### Test sign

```bash
echo -n "message_to_sign" > msg.txt
openssl pkeyutl -sign -inkey user_private.pem -in msg.txt -out msg.sig
```

---

## Эндпоинты

---

### 1. `/reg` — Регистрация пользователя

**Описание:** регистрирует нового пользователя. Запрос должен быть подписан администратором.

**Метод:** POST

**JSON-параметры:**

| Поле | Тип | Описание |  
|------|------|----------|  
| `username` | string | Уникальное имя пользователя |  
| `pub_key` | string | Публичный ключ пользователя (Base64, 32 байта) |  
| `admin_sig` | string | Подпись администратора (Base64, 64 байта) от строки `username+pub_key` |

**Пример запроса:**

```json
{
    "username": "alice",
    "pub_key": "BASE64_PUBLIC_KEY",
    "admin_sig": "BASE64_ADMIN_SIGNATURE"
}
```

**Ответы:**

```json
{ "success": true, "message": "OK" }
{ "success": false, "message": "User already exists" }
{ "success": false, "message": "Invalid admin signature" }
{ "success": false, "message": "Bad public key format" }
```

**Метрики:**

- `paranoia_reg_success_total`  
- `paranoia_reg_fail_total`

---

### 2. `/push` — Отправка пакета данных

**Описание:** пользователь отправляет пакет данных на сервер.  
Каждый пакет идентифицируется уникальным `seq`.

**Метод:** POST

**JSON-параметры:**

| Поле | Тип | Описание |  
|------|------|----------|  
| `username` | string | Имя пользователя |  
| `seq` | uint64 | Уникальный монотонно возрастающий номер пакета |  
| `payload` | string | Данные пакета (Base64) |  
| `sig` | string | Подпись пользователя (Base64, 64 байта) от строки `username+seq+payload` |

**Пример запроса:**

```json
{
    "username": "alice",
    "seq": 1,
    "payload": "BASE64_DATA",
    "sig": "BASE64_SIGNATURE"
}
```

**Ответы:**

```json
{ "success": true, "message": "OK" }
{ "success": false, "message": "Not registered" }
{ "success": false, "message": "Invalid signature" }
{ "success": false, "message": "Duplicate seq" }
```

**Требования корректности:**

- `seq` должен быть уникальным в рамках пользователя.  
- Повторная отправка уже существующего `seq` запрещена.  

**Метрики:**

- `paranoia_push_success_total`  
- `paranoia_push_fail_total`

---

### 3. `/pull` — Получение пакетов

**Описание:** пользователь получает пакеты с `seq > after_seq`.

**Метод:** POST

**JSON-параметры:**

| Поле | Тип | Описание |  
|------|------|----------|  
| `username` | string | Имя пользователя |  
| `after_seq` | uint64 | Последний полученный номер |  
| `sig` | string | Подпись пользователя от строки `username+after_seq` |

**Пример запроса:**

```json
{
    "username": "alice",
    "after_seq": 10,
    "sig": "BASE64_SIGNATURE"
}
```

**Пример ответа при успехе:**

```json
{
    "success": true,
    "message": [
        { "seq": 11, "payload": "BASE64_DATA" },
        { "seq": 12, "payload": "BASE64_DATA" }
    ]
}
```

**Метрики:**

- `paranoia_pull_success_total`  
- `paranoia_pull_fail_total`

---

### 4. `/determinate` — Удаление пакетов пользователя до указанного номера

**Описание:** удаляет все пакеты пользователя с `seq <= after_seq`.

**Метод:** POST

**JSON-параметры:**

| Поле | Тип | Описание |  
|------|------|----------|  
| `username` | string | Имя пользователя |  
| `after_seq` | uint64 | Удалить все пакеты с `seq <= after_seq` |  
| `sig` | string | Подпись пользователя от строки `username+after_seq` |

**Пример запроса:**

```json
{
    "username": "alice",
    "after_seq": 42,
    "sig": "BASE64_SIGNATURE"
}
```

**Ответы:**

```json
{ "success": true, "message": "OK" }
{ "success": false, "message": "Not registered" }
{ "success": false, "message": "Invalid signature" }
```

**Семантика:**

- Удаляются только записи с `seq <= after_seq`.  
- Запрос идемпотентен.

**Метрики:**

- `paranoia_determinate_success_total`  
- `paranoia_determinate_fail_total`

---

## Примечания по безопасности

- Все подписи проверяются с использованием Ed25519.  
- Сервер не доверяет неподписанным данным.  
- Повторное использование `seq` запрещено.
