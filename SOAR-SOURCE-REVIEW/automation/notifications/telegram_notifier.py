import requests
from automation.config.telegram_config import BOT_TOKEN, CHAT_ID


class TelegramNotifier:

    def __init__(self):
        self.url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    def send(self, message):

        payload = {
            "chat_id": CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }

        response = requests.post(
            self.url,
            json=payload,
            timeout=10
        )

        return response