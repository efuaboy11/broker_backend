# yourapp/backends.py
from django.contrib.auth.backends import ModelBackend
from .models import NewUser


def authenticate(email=None, password=None, **kwargs):
    try:
        user = NewUser.objects.get(email=email)
        if user.check_password(password):
            return user
    except NewUser.DoesNotExist:
        return None
