from django.urls import path
from .views import *


urlpatterns = [
    # Register APIs
    path('regiser/bank/', RegisterBank.as_view(), name='register-bank'),
    path('register/customer/', RegisterCustomer.as_view(), name='register-customer'),
    path('register/account/', RegisterAccount.as_view(), name='register-account'),
    path('register/loan/', RegisterLoan.as_view(), name='register-loan'),

    # CRUD APIs
    path('bank/', LC_Bank.as_view(), name='List-Create-bank'),
    path('bank/<uuid:pk>/', RUD_Bank.as_view(), name='Retrieve-Update-Delete-bank'),

    path('customer/', LC_Customer.as_view(), name='List-Create-customer'),
    path('customer/<uuid:pk>/', RUD_Customer.as_view(), name='Retrieve-Update-Delete-customer'),

    path('account/', LC_Account.as_view(), name='List-Create-account'),
    path('account/<uuid:pk>/', RUD_Account.as_view(), name='Retrieve-Update-Delete-account'),

    path('loan/', LC_Loan.as_view(), name='List-Create-loan'),
    path('loan/<uuid:pk>/', RUD_Loan.as_view(), name='Retrieve-Update-Delete-loan'),

    # Prediction API
    path('loan/predict/', PredictLoanStatus.as_view(), name='predict-loan-status'),
]