import time
from twilio.rest import Client
from config import Config

TO_NUMBER = "whatsapp:+918329844326"

print("\n--- SecureLogin AI WhatsApp Diagnostic ---")
print("Account SID loaded:", bool(Config.TWILIO_ACCOUNT_SID))
print("Auth Token loaded:", bool(Config.TWILIO_AUTH_TOKEN))
print("Sender:", Config.TWILIO_WHATSAPP_NUMBER)
print("Content SID:", Config.TWILIO_CONTENT_SID)

client = Client(
    Config.TWILIO_ACCOUNT_SID,
    Config.TWILIO_AUTH_TOKEN
)

try:
    message = client.messages.create(
        from_=Config.TWILIO_WHATSAPP_NUMBER,
        to=TO_NUMBER,
        content_sid=Config.TWILIO_CONTENT_SID
    )

    print("\nMessage accepted by Twilio")
    print("SID:", message.sid)
    print("Initial status:", message.status)

    print("\nWaiting 10 seconds for delivery status...")
    time.sleep(10)

    result = client.messages(message.sid).fetch()

    print("\n--- FINAL RESULT ---")
    print("SID:", result.sid)
    print("Status:", result.status)
    print("Error Code:", result.error_code)
    print("Error Message:", result.error_message)

except Exception as e:
    print("\n--- REQUEST FAILED ---")
    print(e)