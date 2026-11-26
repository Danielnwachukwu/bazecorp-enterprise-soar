from automation.notifications.telegram_notifier import TelegramNotifier

bot = TelegramNotifier()

response = bot.send(
    """
🚨 TEST MESSAGE

Your Telegram integration is working.

Daniel's SOC Automation Framework
"""
)

print(response.status_code)
print(response.text)