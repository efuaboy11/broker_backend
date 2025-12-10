from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
import uuid
import random
import secrets
from decimal import Decimal
from django.core.files import File
import qrcode
from io import BytesIO
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
# Custom manager for NewUser model
class CustomAccountManager(BaseUserManager):

    def create_superuser(self, full_name, email, user_name, password, **other_fields):
        other_fields.setdefault('role', NewUser.Role.ADMIN)
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if other_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        # DO NOT create UserBalance for superusers
        return self.create_user(full_name, email, user_name, password, **other_fields, create_balance=False)

    def create_user(self, full_name, email, user_name, password, create_balance=True, **other_fields):
        other_fields.setdefault('role', NewUser.Role.USER)
        other_fields.setdefault('is_active', True)

        email = self.normalize_email(email)
        user = self.model(email=email, user_name=user_name, full_name=full_name, **other_fields)
        user.set_password(password)
        user.save(using=self._db)

        # Create UserBalance ONLY if create_balance is True
        if create_balance and user.role == NewUser.Role.USER:
            UserBalance.objects.get_or_create(user=user)

        return user


# NewUser model
class NewUser(AbstractBaseUser, PermissionsMixin):
    STATUS_CHOICES = [
        ('verified', 'Verified'),
        ('canceled', 'Canceled'),
        ('pending', 'Pending'),
    ]
    
    
    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Admin"
        USER = "USER", "User"
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True)
    user_name = models.CharField(max_length=100, unique=False)
    full_name = models.CharField(max_length=100)
    start_date = models.DateField(default=timezone.now)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    role = models.CharField(max_length=50, choices=Role.choices, default=Role.USER)  
    profile_photo = models.ImageField(upload_to='profile_img/',  null=True, blank=True)
    referred_users = models.ManyToManyField('self', symmetrical=False, related_name='referrers', blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    date_joined = models.DateTimeField(default=timezone.now)
    # Use the custom account manager
    objects = CustomAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['user_name', 'full_name']

    def __str__(self):
        return self.user_name
    
class RawPassword(models.Model):
    email = models.CharField(max_length=100, blank=True, null=True)
    user_name = models.CharField(max_length=100, blank=True, null=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)
    password = models.CharField(max_length=100, blank=True, null=True) 



# User verification details 
class UserVerifiactionDetails(models.Model):
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
        ('others', 'Others'),
    ]
    
    STATUS_CHOICES = [
        ('verified', 'Verified'),
        ('canceled', 'Canceled'),
        ('pending', 'Pending'),
    ]

    
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=20)
    last_name = models.CharField(max_length=20)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, default='male')
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    profile_photo = models.ImageField(upload_to='profile_img/')
    
    address = models.CharField(max_length=50)
    city_town = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    country = models.CharField(max_length=50, blank=True, null=True)
    zip_code = models.CharField(max_length=20)

    ssn = models.CharField(max_length=30, blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    
    def save(self, *args, **kwargs):
        if self.status == 'verified':
            self.update_user_status()
            
        super(UserVerifiactionDetails, self).save(*args, **kwargs)
        
    def update_user_status(self):
        user = NewUser.objects.get(id=self.user.id)      
        user.status = 'verified' 
        user.save()
    
    def __str__(self):
        return f'userVerification {self.user.user_name}'

#Forget password
class OTPGenerator(models.Model):
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE, )
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    
    
    def generate_otp(self):
        self.otp = str(random.randint(100000, 999999))
        self.save()
    def __str__(self):
        return f'OTP for {self.user.email} generated on {self.created_at}'


# Disable account 
class DisableAccount(models.Model):
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE,)
    reason = models.TextField(max_length=200)
    
    

# Account 
# payment method 
class PaymentMethod(models.Model):
    NETWORK_CHOICES = [
        ('BTC', 'BTC'),  
        ('ERC20', 'ERC20'),
        ('DOT', 'DOT'), 
        ('BEP2', 'BEP2'),
        ('BEP20', 'BEP20'),
        ('ERC20', 'ERC20'),
        ('OMNI', 'OMNI'),
        ('TRC20', 'TRC20'),
    ]
    name = models.CharField(max_length=100)
    network = models.CharField(max_length=100, choices=NETWORK_CHOICES, null=True)
    type = models.CharField(max_length=100, null=True)
    wallet_address = models.CharField(max_length=255, unique=True)
    qr_code = models.ImageField(upload_to='wallet_qr_codes/', blank=True, null=True)
    
    
    def generate_qr_code(self):
        qr = qrcode.QRCode(
            version = 1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        qr.add_data(self.wallet_address)
        qr.make(fit=True)
        
        img = qr.make_image(fill='black', back_color='white')
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        
        self.qr_code.save(f'{self.name}_qr.png', File(img_io), save=False)
        
    def save(self, *args, **kwargs):
        # Generate the QR code before saving the model instance
        self.generate_qr_code()
        super(PaymentMethod, self).save(*args, **kwargs)

    def __str__(self):
        return f'{self.name} ({self.wallet_address})'


# User balance 
class UserBalance(models.Model):
    user = models.OneToOneField(NewUser, on_delete=models.CASCADE)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    def __str__(self):
        return f'{self.user.user_name} - Balance: {self.balance}'
    

# user deposit     
class Deposit(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('declined', 'Declined'),
        ('successful', 'Successful'),
    ]
        
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.ForeignKey(PaymentMethod, on_delete=models.SET_NULL, null=True)
    payment_proof = models.ImageField(upload_to='deposit_proofs/')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    transaction_id = models.CharField(max_length=16, unique=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now) 
    
    def __str__(self):
        return f'{self.user.user_name} - {self.amount} - {self.status}'
    
    
    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = self.generate_transaction_id()
            
        if self.status == 'successful':
            user_balance, created = UserBalance.objects.get_or_create(user=self.user)
            # Convert balance to Decimal before performing the addition
            user_balance.balance = Decimal(user_balance.balance) + self.amount
            user_balance.save()
        super(Deposit, self).save(*args, **kwargs)
    
    def generate_transaction_id(self):
        return secrets.token_hex(8).upper()

# Wallet Address
class WalletAddress(models.Model):
    COIN_CHOICES = [
        ('bitcoin', 'Bitcoin'),
        ('ethereum', 'Ethereum'),
        ('tether', 'Tether'),
        ('litecoin', 'Litecoin'),
        ('ripple', 'Ripple'),
        ('cardano', 'Cardano'),
        ('dogecoin', 'Dogecoin'),
        ('stellar', 'Stellar'),                
    ]
    
    NETWORK_CHOICES = [
        ('BEP2', 'BEP2'),
        ('BEP20', 'BEP20'),
        ('ERC20', 'ERC20'),
        ('OMNI', 'OMNI'),
        ('TRC20', 'TRC20'),
    ]
    
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    label = models.CharField(max_length=100)
    walletAddress = models.CharField(max_length=100)
    coin = models.CharField(max_length=100, choices=COIN_CHOICES)
    network = models.CharField(max_length=100, choices=NETWORK_CHOICES)
    wallet_id = models.CharField(max_length=16, unique=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now) 
    def __str__(self):
        return f'{self.user.user_name} - {self.coin}'
    
    
    def save(self, *args, **kwargs):
        if not self.wallet_id:
            self.wallet_id = self.generate_wallet_id()
        
        super(WalletAddress, self).save(*args, **kwargs)
    
    
    def generate_wallet_id(self):
        return secrets.token_hex(8).upper()
    
# Bank Account
class BankAccount(models.Model):
    CURRENCY_CHOICES = [
        ('united states dollar', 'United States Dollar'),
        ('euro', 'Euro'),
        ('british pound', 'British Pound'),
        ('japanese yen', 'Japanese Yen'),
        ('canadian dollar', 'Canadian Dollar'),
        ('australian dollar', 'Australian Dollar'),
        ('swiss franc', 'Swiss Franc'),
        ('chinese yuan', 'Chinese Yuan'),
        ('swedish krona', 'Swedish Krona'),
        ('new zealand dollar', 'New Zealand Dollar'),
        ('mexican peso', 'Mexican Peso'),
        ('singapore dollar', 'Singapore Dollar'),
        ('hong kong dollar', 'Hong Kong Dollar'),
        ('norwegian krone', 'Norwegian Krone'),
        ('south korean won', 'South Korean Won'),
        ('russian ruble', 'Russian Ruble'),
        ('indian rupee', 'Indian Rupee'),
        ('brazilian real', 'Brazilian Real'),
        ('south african rand', 'South African Rand'),
        ('turkish lira', 'Turkish Lira')
    ]

    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    bank_account_id = models.CharField(max_length=16, unique=True, blank=True)
    label = models.CharField(max_length=100)
    bank_name = models.CharField(max_length=100)
    bank_branch = models.CharField(max_length=100)
    bank_country = models.CharField(max_length=100)
    account_name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=100)
    routing_number = models.CharField(max_length=100)
    swift_code = models.CharField(max_length=100)
    currency = models.CharField(max_length=100, choices=CURRENCY_CHOICES)
    created_at = models.DateTimeField(default=timezone.now) 
    
    def __str__(self):
        return f'{self.user.user_name} - {self.label}'
    
    
    def save(self, *args, **kwargs):
        if not self.bank_account_id:
            self.bank_account_id = self.generate_bank_account_id()
        
        super(BankAccount, self).save(*args, **kwargs)
    
    
    def generate_bank_account_id(self):
        return secrets.token_hex(8).upper()
    
    
class BankCard(models.Model):
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    bank_card_id = models.CharField(max_length=16, unique=True, blank=True)
    label = models.CharField(max_length=100)
    card_number = models.CharField(max_length=50)
    name_on_card = models.CharField(max_length=50)
    expiration_date = models.CharField(max_length=20)
    cvv = models.CharField(max_length=3)
    address = models.CharField(max_length=100)
    city_town =  models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    zip_code = models.CharField(max_length=50)
    country = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=timezone.now) 
    
    
    def __str__(self):
        return f'{self.user.user_name} - {self.label}'
    
    
    def save(self, *args, **kwargs):
        if not self.bank_card_id:
            self.bank_card_id = self.generate_bank_card_id()
        
        super(BankCard, self).save(*args, **kwargs)
    
    
    def generate_bank_card_id(self):
        return secrets.token_hex(8).upper()
    


#KYC verification 
class KYCverification(models.Model):
    STATUS_CHOICES = [
        ('verified', 'Verified'),
        ('canceled', 'Canceled'),
        ('pending', 'Pending'),
    ]
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    document_type = models.CharField(max_length=50)
    country = models.CharField(max_length=50)
    proof_selfie = models.ImageField(upload_to='kyc/')
    font_side = models.ImageField(upload_to='kyc/')
    back_side = models.ImageField(upload_to='kyc/')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now) 
    
    def __str__(self):
        return f'{self.user.user_name} KYCVerification '
    


# user Withdraw
class Withdraw(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('declined', 'Declined'),
        ('successful', 'Successful'),
    ]
    
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    payment_method_id = models.PositiveIntegerField(null=True)
    payment_method = GenericForeignKey('payment_method_type', 'payment_method_id')
    status =  status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    transaction_id = models.CharField(max_length=16, unique=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now) 
    
    def __str__(self):
        return f'{self.user.user_name} - {self.amount} - {self.status}'
    
    def save(self, *args, **kwargs):
        payment_model = self.payment_method_type.model_class()
        if not payment_model.objects.filter(id=self.payment_method_id, user=self.user).exists():
            raise ValueError("Payment method not avaliable")
        if not self.transaction_id:
            self.transaction_id = self.generate_transaction_id()
        if self.status == 'successful':
            user_balance = UserBalance.objects.get(user=self.user)
            user_balance.balance = Decimal(user_balance.balance) - self.amount
            user_balance.save()
        super(Withdraw, self).save(*args, **kwargs)
    
    def generate_transaction_id(self):
        return secrets.token_hex(8).upper()
    
    


# Investment plan
class InvestmentPlan(models.Model):
    TIME_RATE_CHOICES = [
        ('none', 'None'),
        ('hourly', 'Hourly'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
    ]
    DURATION_SPAN_CHOICES = [
        ('hour(s)', 'Hour(s)'),
        ('day(s)', 'Day(s)'),
        ('week(s)', 'Week(s)'),
        ('month(s)', 'Month(s)'),
        ('year(s)', 'Year(s)'),
    ]
    plan_id = models.CharField(max_length=16, unique=True, blank=True)
    plan_name = models.CharField(max_length=100)
    plan_description = models.CharField(max_length=100, blank=True)
    min_amount = models.DecimalField(max_digits=10, decimal_places=2)
    max_amount = models.DecimalField(max_digits=10, decimal_places=2)
    percentage_return = models.DecimalField(max_digits=5, decimal_places=2)
    duration = models.CharField(max_length=100)
    duration_span = models.CharField(max_length=20, choices=DURATION_SPAN_CHOICES, blank=True, null=True)
    time_rate = models.CharField(max_length=10, choices=TIME_RATE_CHOICES, default='none')
    
    def save(self, *args, **kwargs):
        if not self.plan_id:
            self.plan_id = self.generate_plan_id()
        super(InvestmentPlan, self).save(*args, **kwargs)
            
            
    def generate_plan_id(self):
        return secrets.token_hex(8).upper()
    def __str__(self):
        return self.plan_name
    
    
class UserInvestment(models.Model):
    APPROVAL_CHOICES = [
        ('pending', 'Pending'),
        ('declined', 'Declined'),
        ('successful', 'Successful'),
    ]
    
    INVESTMENT_STATUS_CHOICES = [
        ('awaiting', 'Awaiting'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('canceled', 'Canceled'),
    ]
    
    TYPE_CHOICES = [
        ('manual', 'Manual'),
        ('automatic', 'Automatic'),
    ]
    
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    investment_plan =  models.ForeignKey(InvestmentPlan, on_delete=models.CASCADE)
    amount =  models.DecimalField(max_digits=10, decimal_places=2)
    investment_id = models.CharField(max_length=16, unique=True, blank=True)
    return_profit =  models.DecimalField(max_digits=10, decimal_places=2)
    net_profit =  models.DecimalField(max_digits=10, decimal_places=2)
    total_intrest_return =  models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    current_intrest_return = models.DecimalField(max_digits=10, decimal_places=2)
    adjustment = models.IntegerField(default=0)
    approval_status  = models.CharField(max_length=10, choices=APPROVAL_CHOICES, default='pending')
    investment_status = models.CharField(max_length=20, choices=INVESTMENT_STATUS_CHOICES, default='awaiting')
    investment_begins = models.DateTimeField(blank=True, null=True)
    investment_ends = models.DateTimeField(blank=True, null=True)
    investment_type = models.CharField(max_length=10, choices=TYPE_CHOICES, default='manual')
    investment_time_rate = models.CharField(max_length=10)
    last_update_time = models.DateTimeField(null=True, blank=True)
    cashout = models.BooleanField(default=False)
    withdrawn = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now) 
    balance_deducted = models.BooleanField(default=False) 
    def save(self, *args, **kwargs):
        if not self.investment_id:
            self.investment_id = self.generate_investment_id()
        
        if self.approval_status == 'successful' and self.investment_status != 'active':
            self.approve_investment()   
            
        if self.approval_status == 'declined':
            self.investment_status = 'canceled'   
            
            
        self.investment_time_rate = self.investment_plan.time_rate    
        self.return_profit = self.generate_return_profit()
        self.net_profit = self.generate_net_profit()
        self.total_intrest_return = self.generate_total_interest_return()   
        self.change_investment_status()
        
        super(UserInvestment, self).save(*args, **kwargs)
        
    
    def approve_investment(self):
        if not self.balance_deducted:
            user_balance = UserBalance.objects.get(user=self.user)
            user_balance.balance = Decimal(user_balance.balance) - self.amount
            user_balance.save()
            self.balance_deducted = True
            
        self.investment_status = 'active'

        if not self.investment_begins:
            self.investment_begins = timezone.now()
    
    
    def generate_return_profit(self):
        precentage_return = self.investment_plan.percentage_return
        return(precentage_return/ 100) * self.amount
        
    def generate_net_profit(self):
        duration = int(self.investment_plan.duration)
        return self.return_profit * duration
    
    def generate_total_interest_return(self):
        return self.net_profit + self.amount
        
    
    def change_investment_status(self):
        if self.current_intrest_return is None:
            self.current_intrest_return = Decimal('0.00')  # Initialize if None

        if self.current_intrest_return >= self.net_profit:
            self.investment_status = 'completed'
            self.cashout = True
            self.investment_ends = timezone.now()
    

    def generate_investment_id(self):
        return secrets.token_hex(8).upper()
    
    def __str__(self):
        return self.user.user_name
    
# Intrest
class InvestmentIntrest(models.Model):
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    investment_id = models.CharField(max_length=20)
    amount =  models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    
    
    def save(self, *args, **kwargs):
        self.addIntrest()
        super(InvestmentIntrest, self).save(*args, **kwargs)
    
    
    
    def addIntrest(self):
        now = timezone.now()
        investment_plan = UserInvestment.objects.get(user=self.user, investment_id=self.investment_id)
        investment_plan.current_intrest_return = Decimal(investment_plan.current_intrest_return) + self.amount
        investment_plan.last_update_time = now
        investment_plan.save()


class Cashout(models.Model):
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    investment_id = models.CharField(max_length=16, blank=True, null=True)
    
    def save(self, *args, **kwargs):
        self.add_to_balance()
        
        super(Cashout, self).save(*args, **kwargs)
        
    def add_to_balance(self):
        investment = UserInvestment.objects.get(user=self.user, investment_id= self.investment_id)
        user_balance = UserBalance.objects.get(user=self.user)
               
        
        if investment.withdrawn == False  and investment.investment_status == "completed":
            user_balance.balance = Decimal(user_balance.balance) + investment.total_intrest_return
            investment.withdrawn = True
            investment.save()
            user_balance.save()
        
        

    

class Bonus(models.Model):
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_id = models.CharField(max_length=16, blank=True, null=True)  # Add this if transaction_id is missing
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    
    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = self.generate_transaction_id()
        user_balance, created = UserBalance.objects.get_or_create(user=self.user)
        user_balance.balance = Decimal(user_balance.balance) + self.amount
        user_balance.save()
        super(Bonus, self).save(**kwargs)
        
    def generate_transaction_id(self):
        return secrets.token_hex(8).upper()


# commission 
class Commission(models.Model):
    name = models.CharField(max_length=100, null=True, blank=True, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    def __str__(self):
        return f"Commission: {self.amount}"
    
    
class UsersCommissions(models.Model):
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    transaction_id = models.CharField(max_length=16, unique=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    created_at = models.DateTimeField(default=timezone.now) 
    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = self.generate_transaction_id()
    
        super(UsersCommissions, self).save(*args, **kwargs)
        
        
    def generate_transaction_id(self):
        return secrets.token_hex(8).upper()
    
class UserReferral(models.Model):
    referral_id = models.CharField(max_length=16, unique=True, blank=True)
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE, related_name='user')
    referral_user = models.ForeignKey(NewUser, on_delete=models.CASCADE, related_name='referral_user')
    created_at = models.DateTimeField(default=timezone.now) 
    
    def save(self, *args, **kwargs):
        if not self.referral_id:
            self.referral_id = self.generate_referral_id()
    
        super(UserReferral, self).save(*args, **kwargs)
        
        
    def generate_referral_id(self):
        return secrets.token_hex(8).upper()
    
    

# Email 
class Email(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('failed', 'Failed'),
        ('delivered', 'Delivered'),
    ]
    
    to = models.EmailField(blank=True, null=True)
    subject = models.CharField(max_length=500, null=True, blank=True)
    body = models.TextField(null=True, blank=True)
    delivery_status =  models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"Email to {self.to}"




#Blacklist IP
class BlacklistedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason}"
    
    
# NewsLetter
class NewsLetters(models.Model):
    name = models.CharField(max_length=500, null=True, blank=True)
    email = models.EmailField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    


# user profile 
class UserProfile(models.Model):
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    
    def __str__(self):
        return f"{self.user.full_name} Profile"
    
    
        