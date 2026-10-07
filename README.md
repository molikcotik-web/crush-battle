# TopGift backend — запуск

1. Бот: @BotFather → отримати `BOT_TOKEN`. Згенерувати секрет: `python3 -c "import secrets;print(secrets.token_urlsafe(32))"`
2. Запуск (потрібен HTTPS-домен, напр. за Caddy/nginx/Render/Fly):
   ```
   export BOT_TOKEN=... WEBHOOK_SECRET=... ALLOWED_ORIGIN=https://YOU.github.io
   python3 server.py
   ```
3. Вебхук Telegram (секрет у шляху І в заголовку):
   ```
   curl "https://api.telegram.org/bot$BOT_TOKEN/setWebhook" \
     -d "url=https://YOUR_HOST/webhook/$WEBHOOK_SECRET" \
     -d "secret_token=$WEBHOOK_SECRET" \
     -d 'allowed_updates=["message","pre_checkout_query"]'
   ```
4. У `index.html` змініть `STARS_INVOICE_ENDPOINT` на `https://YOUR_HOST/api/create-star-invoice`.
5. Тести: `python3 test_server.py`

## Поповнення TON
- Адреса отримувача вже прописана в `.env.example`: `TON_RECEIVER=UQA5_-Yj6MlFFbVAd9Ewp2vdo6kSP4Y4JY6ayawedhUjOXPo` (сервер перевіряє її контрольну суму при старті).
- Швидкий старт: `cp .env.example .env`, заповніть `BOT_TOKEN`, `WEBHOOK_SECRET`, `ALLOWED_ORIGIN`, далі `./run.sh`.
- Раніше: додайте змінні: `TON_RECEIVER=<адреса вашого гаманця>` (+ `TONCENTER_KEY` з @tonapibot для вищих лімітів).
- Розмістіть `tonconnect-manifest.json` поруч з `index.html` (url має збігатися з доменом застосунку, iconUrl — PNG 180×180) і вкажіть його в `MANIFEST_URL` у `index.html`.
- Як це працює: сервер видає заявку з унікальним коментарем → гравець підтверджує переказ у гаманці →
  фоновий сканер (кожні 15 с) і запит статусу знаходять транзакцію в блокчейні та зараховують її один раз.
- Тестнет: `TONCENTER_URL=https://testnet.toncenter.com/api/v2` і тестнет-адреса.
