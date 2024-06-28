from .base import *
import os
from dotenv import load_dotenv
from core.utils import str2bool

load_dotenv('env/.env.prod')

SECRET_KEY = os.getenv('SECRET_KEY')

DEBUG = False

ALLOWED_HOSTS = os.getenv('ALLOWED_HOST').split(',')

CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS').split(',')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DATABASE_NAME'),
        'USER': os.getenv('USERNAME'),
        'PASSWORD': os.getenv('PASSWORD'),
        'HOST': os.getenv('HOST'),
        'PORT': os.getenv('PORT'),
    }
}

SIMPLE_JWT['SIGNING_KEY'] = os.getenv('SECRET_KEY')
SIMPLE_JWT['AUTH_COOKIE_SECURE'] = str2bool(os.getenv('COOKIE_SECURE'))
SIMPLE_JWT['AUTH_COOKIE_DOMAIN'] = os.getenv('AUTH_COOKIE_DOMAIN', default=None)

SESSION_COOKIE_SECURE = str2bool(os.getenv('COOKIE_SECURE'))
CSRF_COOKIE_SECURE = str2bool(os.getenv('COOKIE_SECURE'))

CSRF_TRUSTED_ORIGINS = os.getenv('CSRF_TRUSTED_ORIGINS').split(',')

REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'] = [os.getenv('DEFAULT_PERMISSION_CLASSES', 'rest_framework.permissions.IsAuthenticated')]
