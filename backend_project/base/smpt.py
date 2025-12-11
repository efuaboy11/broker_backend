import smtplib
from email.mime.text import MIMEText
from django.conf import settings
from time import sleep
from .models import Email
def send_email(to_email, message, subject):
    msg = MIMEText(message, 'html') 
    msg['Subject'] = f'{subject}'
    msg['From'] = settings.DEFAULT_FROM_EMAIL
    msg['To'] = to_email

    try:
        with smtplib.SMTP('smtp.hostinger.com', 465) as server:
            server.starttls()
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            server.send_message(msg)
        print("email sent successfully.")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False




# def send_email(to_email, message, subject):
#     msg = MIMEText(message, 'html')
#     msg['Subject'] = subject
#     msg['From'] = settings.DEFAULT_FROM_EMAIL
#     msg['To'] = to_email

#     try:
#         # Use Django SMTP settings dynamically
#         server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)

#         if getattr(settings, "EMAIL_USE_TLS", False):
#             server.starttls()

#         if getattr(settings, "EMAIL_USE_SSL", False):
#             # smtplib uses SMTP_SSL for SSL connections
#             server = smtplib.SMTP_SSL(settings.EMAIL_HOST, settings.EMAIL_PORT)

#         server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
#         server.send_message(msg)
#         server.quit()

#         print("Email sent successfully.")
#         return True
#     except Exception as e:
#         print(f"Failed to send email: {e}")
#         return False
    
    
    
def send_bulk_email(email_list, message, subject, text, is_bulk):
    
    delivery_status = {email: 'pending' for email in email_list}
    if not is_bulk:
        success = send_email(email_list, message, subject)
        result = 'delivered' if success else 'failed'
        Email.objects.create(to=email_list, subject=subject, body=text, delivery_status=result)
        
        
        
        
    def process_emails(emails_to_send):
        for email in emails_to_send:
            success = send_email(email, message, subject)
            result = 'delivered' if success else 'failed'
            delivery_status[email] = 'delivered' if success else 'failed'
            Email.objects.create(to=email, subject=subject, body=text, delivery_status=result)
            
    if is_bulk:
        process_emails(email_list)
    
        no_time_ran = 0
        while True:
            failed_emails = [email for email, status in delivery_status.items() if status == 'failed']
            if len(failed_emails) <= 10 or no_time_ran == 5:
                break
            
            print(f"Retrying failed emails: {failed_emails}")
            process_emails(failed_emails)
            no_time_ran += 1
            
            sleep(5)
        
    print(f"Final delivery status: {delivery_status}")   
    return delivery_status