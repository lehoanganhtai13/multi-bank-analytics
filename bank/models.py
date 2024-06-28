import uuid

from django.db import models

from users.models import CustomUser


class Bank(models.Model):
    """
    Model for bank information.
    """
    bank_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    bank_name = models.CharField(max_length=255)
    manager = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    address = models.TextField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=255, blank=True, null=True)
    state = models.CharField(max_length=255, blank=True, null=True)
    zip_code = models.CharField(max_length=255, blank=True, null=True)
    country = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.bank_name
    

class Customer(models.Model):
    """
    Model for customer information.
    """

    YEARS_IN_JOB_CHOICES = [
        ('< 1 year', '< 1 year'),
        ('1 year', '1 year'),
        ('2 years', '2 years'),
        ('3 years', '3 years'),
        ('4 years', '4 years'),
        ('5 years', '5 years'),
        ('6 years', '6 years'),
        ('7 years', '7 years'),
        ('8 years', '8 years'),
        ('9 years', '9 years'),
        ('10+ years', '10+ years'),
    ]

    HOME_OWNERSHIP_CHOICES = [
        ('Rent', 'Rent'),
        ('Home Mortgage', 'Home Mortgage'),
        ('Own Home', 'Own Home'),
        ('Have Mortgage', 'Have Mortgage'),
        ('Other', 'Other'),
    ]

    customer_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=128)
    last_name = models.CharField(max_length=128)
    phone = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=255, blank=True, null=True)
    state = models.CharField(max_length=128, blank=True, null=True)
    zip_code = models.CharField(max_length=10, blank=True, null=True)
    country = models.CharField(max_length=128, blank=True, null=True)
    credit_score = models.DecimalField(max_digits=20, decimal_places=2, blank=True, null=True)
    annual_income = models.IntegerField(blank=True, null=True)
    years_in_current_job = models.CharField(max_length=20, choices=YEARS_IN_JOB_CHOICES, blank=True, null=True)
    home_ownership = models.CharField(max_length=20, choices=HOME_OWNERSHIP_CHOICES, blank=True, null=True)
    years_of_credit_history = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    number_of_open_accounts = models.IntegerField(blank=True, null=True)
    number_of_credit_problems = models.IntegerField(blank=True, null=True)
    bankruptcies = models.IntegerField(blank=True, null=True)
    tax_liens = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return self.first_name + ' ' + self.last_name


class Account(models.Model):
    """
    Model for bank account information.
    """
    account_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    account_number = models.CharField(max_length=255)
    date_opened = models.DateField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    monthly_debt = models.DecimalField(max_digits=20, decimal_places=2, blank=True, null=True)
    current_credit_balance = models.DecimalField(max_digits=20, decimal_places=2, blank=True, null=True)
    maximum_open_credit = models.IntegerField(blank=True, null=True)
    months_since_last_delinquent = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return self.account_number


class Loan(models.Model):
    """
    Model for loan information.
    """

    TERM_CHOICES = [
        ('Short Term', 'Short Term'),
        ('Long Term', 'Long Term'),
    ]

    LOAN_STATUS_CHOICES = [
        ('Fully Paid', 'Fully Paid'),
        ('Charged Off', 'Charged Off'),
    ]

    loan_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    current_loan_amount = models.DecimalField(max_digits=20, decimal_places=2)
    term = models.CharField(max_length=20, choices=TERM_CHOICES)
    purpose = models.TextField(max_length=255)
    loan_status = models.CharField(max_length=20, choices=LOAN_STATUS_CHOICES)

    def __str__(self):
        return self.loan_id
