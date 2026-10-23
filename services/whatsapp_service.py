from twilio.rest import Client
from config import Config


def format_whatsapp_recipient(phone_number: str) -> str:
    number = str(phone_number).strip().replace(" ", "").replace("-", "")

    if number.startswith("whatsapp:"):
        return number

    if not number.startswith("+"):
        number = "+91" + number

    return "whatsapp:" + number


def send_whatsapp_security_alert(
    recipient_number: str,
    failed_count: int,
    ip_address: str
) -> bool:

    print("\n======================================")
    print("SECURELOGIN WHATSAPP ALERT STARTED")
    print("======================================")

    try:
        print("Recipient from database:", recipient_number)
        print("Failed attempts:", failed_count)
        print("IP:", ip_address)

        print("Account SID loaded:",
              bool(Config.TWILIO_ACCOUNT_SID))

        print("Auth Token loaded:",
              bool(Config.TWILIO_AUTH_TOKEN))

        print("Sender:",
              Config.TWILIO_WHATSAPP_NUMBER)

        print("Content SID:",
              Config.TWILIO_CONTENT_SID)

        # Check configuration
        if not Config.TWILIO_ACCOUNT_SID:
            print("ERROR: TWILIO_ACCOUNT_SID missing")
            return False

        if not Config.TWILIO_AUTH_TOKEN:
            print("ERROR: TWILIO_AUTH_TOKEN missing")
            return False

        if not Config.TWILIO_WHATSAPP_NUMBER:
            print("ERROR: TWILIO_WHATSAPP_NUMBER missing")
            return False

        if not Config.TWILIO_CONTENT_SID:
            print("ERROR: TWILIO_CONTENT_SID missing")
            return False

        # Create client
        client = Client(
            Config.TWILIO_ACCOUNT_SID,
            Config.TWILIO_AUTH_TOKEN
        )

        # Format recipient
        target_number = format_whatsapp_recipient(
            recipient_number
        )

        sender_number = Config.TWILIO_WHATSAPP_NUMBER.strip()

        if not sender_number.startswith("whatsapp:"):
            sender_number = "whatsapp:" + sender_number

        print("--------------------------------------")
        print("SENDING WHATSAPP")
        print("FROM:", sender_number)
        print("TO:", target_number)
        print("CONTENT SID:", Config.TWILIO_CONTENT_SID)
        print("--------------------------------------")

        # SAME REQUEST AS WORKING TEST
        message = client.messages.create(
            from_=sender_number,
            to=target_number,
            content_sid=Config.TWILIO_CONTENT_SID
        )

        print("TWILIO ACCEPTED MESSAGE")
        print("MESSAGE SID:", message.sid)
        print("STATUS:", message.status)
        print("======================================\n")

        return True

    except Exception as e:

        print("\n!!!!!!!! WHATSAPP ERROR !!!!!!!!")
        print("ERROR TYPE:", type(e).__name__)
        print("ERROR:", str(e))
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")

        return False