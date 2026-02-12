# Paranoia Server API

Paranoia — это сервер для безопасного хранения и передачи пакетов данных пользователей с поддержкой подписи и метрик.

---

## Общие требования
- Все запросы используют **HTTP POST** с телом в формате JSON.
- Подписи пользователей и администратора — **Ed25519**.
- Поля, которые передаются в Base64 (`pub_key`, `payload`, `sig`, `admin_sig`), должны быть корректно закодированы.
- Сервер возвращает JSON в формате:
```json
{
    "success": true|false,
    "message": "описание результата или ошибка"
}
```
- Метрики на сервере автоматически обновляются при каждом запросе.

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
openssl pkeyutl -sign -inkey user_private.pem -in msg.txt -out msg.sig -pkeyopt digest:None
```

## Эндпоинты

### 1. `/reg` — Регистрация пользователя
**Описание:** регистрирует нового пользователя. Подписывает администратор.  
**Метод:** POST  

**JSON-параметры:**
| Поле        | Тип     | Описание |
|------------|--------|---------|
| `username` | string | Имя пользователя |
| `pub_key`  | string | Публичный ключ пользователя (Base64, 32 байта) |
| `admin_sig` | string | Подпись администратора (Base64, 64 байта) от строки `"username+pub_key"` |

**Пример запроса:**
```json
{
    "username": "alice",
    "pub_key": "BASE64_ENCODED_PUBLIC_KEY",
    "admin_sig": "BASE64_ADMIN_SIGNATURE"
}
```

**Примеры ответа:**
```json
{ "success": true, "message": "OK" }
{ "success": false, "message": "Bad pubkey or signature" }
{ "success": false, "message": "Exception: ..." }
```

**Метрики:**
- `paranoia_reg_success_total`
- `paranoia_reg_fail_total`

---

### 2. `/push` — Отправка пакета данных
**Описание:** пользователь отправляет пакет данных на сервер.  
**Метод:** POST  

**JSON-параметры:**
| Поле      | Тип     | Описание |
|----------|--------|---------|
| `username` | string | Имя пользователя |
| `seq`      | uint64 | Последовательный номер пакета |
| `payload`  | string | Данные пакета (Base64) |
| `sig`      | string | Подпись пользователя (Base64, 64 байта) от строки `"username+seq+payload"` |

**Пример запроса:**
```json
{
    "username": "alice",
    "seq": 1,
    "payload": "BASE64_ENCODED_DATA",
    "sig": "BASE64_SIGNATURE"
}
```

**Примеры ответа:**
```json
{ "success": true, "message": "OK" }
{ "success": false, "message": "Not registered" }
{ "success": false, "message": "Invalid signature" }
```

**Метрики:**
- `paranoia_push_success_total`
- `paranoia_push_fail_total`

---

### 3. `/pull` — Получение пакетов
**Описание:** пользователь получает пакеты, начиная с заданного номера.  
**Метод:** POST  

**JSON-параметры:**
| Поле      | Тип     | Описание |
|----------|--------|---------|
| `username` | string | Имя пользователя |
| `after_seq` | uint64 | Номер последнего известного пакета, получить следующие |
| `sig`      | string | Подпись пользователя (Base64, 64 байта) от строки `"username+after_seq"` |

**Пример запроса:**
```json
{
    "username": "alice",
    "after_seq": 10,
    "sig": "BASE64_SIGNATURE"
}
```

**Пример ответа (успех):**
```json
{
    "success": true,
    "message": [{"seq":11,"payload":"BASE64_DATA"},{"seq":12,"payload":"BASE64_DATA"}]
}
```

**Метрики:**
- `paranoia_pull_success_total`
- `paranoia_pull_fail_total`

---

### 4. `/determinate` — Удаление всех данных пользователя
**Описание:** полностью удаляет все пакеты пользователя из хранилища.  
**Метод:** POST  

**JSON-параметры:**
| Поле      | Тип     | Описание |
|----------|--------|---------|
| `username` | string | Имя пользователя |
| `after_seq` | uint64 | Номер последнего пакета (подписывается для безопасности) |
| `sig`      | string | Подпись пользователя (Base64, 64 байта) от строки `"username+after_seq"` |

**Пример запроса:**
```json
{
    "username": "alice",
    "after_seq": 42,
    "sig": "BASE64_SIGNATURE"
}
```

**Примеры ответа:**
```json
{ "success": true, "message": "OK" }
{ "success": false, "message": "Not registered" }
{ "success": false, "message": "Invalid user signature" }
```

**Метрики:**
- `paranoia_determinate_success_total`
- `paranoia_determinate_fail_total`

---

### Примечания
- Метрики обновляются автоматически.
- Все подписи проверяются с использованием Ed25519.
- Удаление через `/determinate` безопасно: проверяется подпись пользователя и наличие регистрации.
