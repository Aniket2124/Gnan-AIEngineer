from django.core.mail import send_mail
import random
from django.conf import settings
from .models import User

def send_otp_via_mail(email):
    subject = f'Your account verification email'
    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    message = f'Your OTP is {otp}'
    email_from = settings.EMAIL_HOST
    send_mail(subject, message, email_from, [email])
    user_obj = User.objects.get(email=email)
    user_obj.otp = otp
    user_obj.save()