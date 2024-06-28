from django.db import transaction
from .models import Bank, Customer, Account, Loan
from users.models import CustomUser
import csv
import uuid
from faker import Faker


fake = Faker()

@transaction.atomic
def load_data_from_csv(file_path):
    manager = CustomUser.objects.create_user(username=fake.user_name(), first_name=fake.first_name(), email=fake.email(), password='password.123')
    bank = Bank.objects.create(bank_name=fake.company(), manager=manager, address=fake.address(), city=fake.city(), state=fake.state(), zip_code=fake.zipcode_in_state(), country=fake.country())

    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)

        for row in reader:

            customer = Customer.objects.create(
                # Baisc customer information
                first_name=fake.first_name()[:128],
                last_name=fake.last_name()[:128],
                phone=fake.phone_number()[:20],
                city=fake.city()[:255],
                state=fake.state()[:128],
                zip_code=fake.zipcode()[:10],
                country=fake.country()[:128],

                # Customer financial information
                credit_score=row['Credit Score'] if row['Credit Score'] != '' else None,
                annual_income=row['Annual Income'] if row['Annual Income'] != '' else None,
                years_in_current_job=row['Years in current job'] if row['Years in current job'] != '' else None,
                home_ownership=row['Home Ownership'] if row['Home Ownership'] != '' else None,
                years_of_credit_history=row['Years of Credit History'] if row['Years of Credit History'] != '' else None,
                number_of_open_accounts=row['Number of Open Accounts'] if row['Number of Open Accounts'] != '' else None,
                number_of_credit_problems=row['Number of Credit Problems'] if row['Number of Credit Problems'] != '' else None,
                bankruptcies=row['Bankruptcies'] if row['Bankruptcies'] != '' else None,
                tax_liens=row['Tax Liens'] if row['Tax Liens'] != '' else None,
            )

            account = Account.objects.create(
                bank=bank,
                customer=customer,
                account_number=str(uuid.uuid4()),
                date_opened=fake.date_between(start_date='-30y', end_date='today'),
                is_active=fake.boolean(chance_of_getting_true=50),
                monthly_debt=row['Monthly Debt'] if row['Monthly Debt'] != '' else None,
                current_credit_balance=row['Current Credit Balance'] if row['Current Credit Balance'] != '' else None,
                maximum_open_credit=row['Maximum Open Credit'] if row['Maximum Open Credit'] != '' else None,
                months_since_last_delinquent=row['Months since last delinquent'] if row['Months since last delinquent'] != '' else None,
            )

            Loan.objects.create(
                account=account,
                current_loan_amount=row['Current Loan Amount'] if row['Current Loan Amount'] != '' else None,
                term=row['Term'] if row['Term'] != '' else None,
                purpose=row['Purpose'] if row['Purpose'] != '' else None,
                loan_status=row['Loan Status'] if row['Loan Status'] != '' else None,
            )
