import numpy as np
import pandas as pd
import pickle

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder, OrdinalEncoder, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from django.contrib.auth.models import AnonymousUser

from rest_framework import status, generics, permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from .serializers import *

#=======================Registration APIs=======================

class RegisterBank(generics.CreateAPIView):
    permission_classes = []
    serializer_class = BankSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        bank = response.data

        return Response({
            "message": f"Bank is registered",
            "id": bank['bank_id'],
            "bank name": bank['bank_name']
        }, status=status.HTTP_201_CREATED)
    
class RegisterCustomer(generics.CreateAPIView):
    permission_classes = []
    serializer_class = CustomerSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        customer = response.data

        return Response({
            "message": f"Customer is registered",
            "id": customer['customer_id'],
            "customer name": f"{customer['first_name']} {customer['last_name']}"
        }, status=status.HTTP_201_CREATED)
    
class RegisterAccount(generics.CreateAPIView):
    permission_classes = []
    serializer_class = AccountSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        account = response.data

        return Response({
            "message": f"Account is registered",
            "id": account['account_id'],
            "account number": account['account_number'],
            "bank": account['bank_id']
        }, status=status.HTTP_201_CREATED)

class RegisterLoan(generics.CreateAPIView):
    permission_classes = []
    serializer_class = LoanSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        loan = response.data

        return Response({
            "message": f"Loan is registered",
            "id": loan['loan_id'],
            "loan amount": loan['loan_amount'],
            "account": loan['account_id'],
            "bank": loan['account']['bank_id']
        }, status=status.HTTP_201_CREATED)
    
# =======================CRUD APIs=======================

class IsAdminOrBankManager(permissions.BasePermission):
    """
    Custom permission to only allow admins or the manager of the bank to see it.
    """
    def has_object_permission(self, request, view, obj):
        # Permissions are only allowed to the owner of the snippet
        return request.user.is_staff or obj.manager == request.user

class LC_Bank(generics.ListCreateAPIView):
    serializer_class = BankSerializer

    def get_queryset(self):
        user = self.request.user
        # Check if user is anonymous
        if isinstance(user, AnonymousUser):
            raise PermissionDenied("User is not authenticated")

        if user.is_staff:
            return Bank.objects.all()
        
        return Bank.objects.filter(manager=user)

class RUD_Bank(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BankSerializer
    permission_classes = [IsAdminOrBankManager]

    def get_queryset(self):
        user = self.request.user
        # Check if user is anonymous
        if isinstance(user, AnonymousUser):
            raise PermissionDenied("User is not authenticated")

        if user.is_staff:
            return Bank.objects.all()

        return Bank.objects.filter(manager=user)


class LC_Customer(generics.ListCreateAPIView):
    serializer_class = CustomerSerializer

    def get_queryset(self):
        user = self.request.user
        # Check if user is anonymous
        if isinstance(user, AnonymousUser):
            raise PermissionDenied("User is not authenticated")
        
        return Customer.objects.filter(account__bank__manager=user)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        # Handle the case where there is no pagination
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

class RUD_Customer(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CustomerSerializer

    def get_queryset(self):
        user = self.request.user
        # Check if user is anonymous
        if isinstance(user, AnonymousUser):
            raise PermissionDenied("User is not authenticated")
        
        return Customer.objects.filter(account__bank__manager=user)


class LC_Account(generics.ListCreateAPIView):
    serializer_class = AccountSerializer

    def get_queryset(self):
        user = self.request.user
        # Check if user is anonymous
        if isinstance(user, AnonymousUser):
            raise PermissionDenied("User is not authenticated")
        
        return Account.objects.filter(bank__manager=user)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        # Handle the case where there is no pagination
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

class RUD_Account(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = AccountSerializer

    def get_queryset(self):
        user = self.request.user
        return Account.objects.filter(bank__manager=user)


class LC_Loan(generics.ListCreateAPIView):
    serializer_class = LoanSerializer

    def get_queryset(self):
        user = self.request.user
        # Check if user is anonymous
        if isinstance(user, AnonymousUser):
            raise PermissionDenied("User is not authenticated")
        
        account = self.request.query_params.get('account', None)

        if account is not None:
            return Loan.objects.filter(account__bank__manager=user, account=account)

        return Loan.objects.filter(account__bank__manager=user)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        # Handle the case where there is no pagination
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

class RUD_Loan(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = LoanSerializer

    def get_queryset(self):
        user = self.request.user
        # Check if user is anonymous
        if isinstance(user, AnonymousUser):
            raise PermissionDenied("User is not authenticated")
        
        return Loan.objects.filter(account__bank__manager=user)

# =======================Loan Status Prediction API=======================

with open('./models/best_model.pkl', 'rb') as f:
    model = pickle.load(f)

class PredictLoanStatus(generics.GenericAPIView):
    serializer_class = PredictLoanStatusSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        account_id = serializer.validated_data['account'].account_id
        account = Account.objects.get(account_id=account_id)
        customer = account.customer

        # Prepare the data for prediction
        data = {
            'Current Loan Amount': serializer.validated_data['current_loan_amount'],
            'Term': serializer.validated_data['term'],
            'Credit Score': customer.credit_score,
            'Annual Income': customer.annual_income,
            'Years in current job': customer.years_in_current_job,
            'Home Ownership': customer.home_ownership,
            'Purpose': serializer.validated_data['purpose'],
            'Monthly Debt': account.monthly_debt,
            'Years of Credit History': customer.years_of_credit_history,
            'Months since last delinquent': account.months_since_last_delinquent,
            'Number of Open Accounts': customer.number_of_open_accounts,
            'Number of Credit Problems': customer.number_of_credit_problems,
            'Current Credit Balance': account.current_credit_balance,
            'Maximum Open Credit': account.maximum_open_credit,
            'Bankruptcies': customer.bankruptcies,
            'Tax Liens': customer.tax_liens
        }

        # Convert the data to data frame
        data = pd.DataFrame([data])

        # Make the prediction
        prediction = model.predict(data)
        if prediction[0] == 0:
            result = 'Charged Off'
        else:
            result = 'Fully Paid'

        return Response({'prediction': result}, status=status.HTTP_200_OK)
