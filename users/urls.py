from django.urls import path
from .views import *

urlpatterns = [
    path('register/', Register.as_view(), name='register'),
    path('login/', Login.as_view(), name='login'),
    path('logout/', Logout.as_view(), name='logout'),
    path('token/', RefreshAcessToken.as_view(), name='refresh-access-token'),
    path('auth-status/', AuthStatus.as_view(), name='auth-status'),
]