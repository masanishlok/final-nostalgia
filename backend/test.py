import smtplib

EMAIL = "dialusers@gmail.com"
PASSWORD = "pexo gcgh ztyp mujp"

try:
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(EMAIL, PASSWORD)
    print("✅ SMTP Login Successful!")
    server.quit()
except Exception as e:
    print(f"❌ SMTP Error: {e}")
