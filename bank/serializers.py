from rest_framework import serializers

from .models import *


class BankSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bank
        fields = '__all__'

class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'

class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = '__all__'

class LoanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Loan
        fields = '__all__'

class PredictLoanStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Loan
        fields = ['account', 'current_loan_amount', 'term', 'purpose']