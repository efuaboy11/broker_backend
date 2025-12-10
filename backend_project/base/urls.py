from django.urls import path
from .views import *
from . import views
from django.views.generic import TemplateView

app_name = 'base'

urlpatterns = [
    path("", views.endpoints, name="endpoints"),
    
    path("robots.txt", TemplateView.as_view(template_name="robots.txt", content_type="text/plain")),
    path('users/', Users.as_view(), name='create_user'),
    path('users/<uuid:id>/', UpdateUserView.as_view(), name='user_details'),
    path('users/details/', IndividualUserDetailsViews.as_view(), name='create_user'),
    path('raw-password/', RawPasswordView.as_view(), name='raw-passwords'),
    path('request-otp/', RequestOTPView.as_view(), name='request-otp'),
    path('forget-password/', ForgotPasswordVIew.as_view(), name='verify-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', views.CustomRefreshTokenView.as_view(), name="token_refresh"),
    path('disable-account/', DisableAccountView.as_view(), name='disable-account'),
    path('disable-account/<int:pk>/', DisableAccountRetrieveDelete.as_view(), name='disable-account-delete'),
    
    # User Verification
    path('user/verification/', UserVerifiactionDetailsView.as_view(), name='user-verification'),
    path('user/verification/admin/', UserVerifiactionAdminView.as_view(), name='user-verification-admin'),
    path('user/verification/<str:pk>/', UserVerificationRetriveUpdateView.as_view(), name='user-verification-update'),
    path('users/verification/<str:pk>/update-status/', UserVerificationUpdateStatusView.as_view(), name='user-verification-status'),
    path('users/without-verification/', UsersWithoutVerificationView.as_view(), name='users-without-verification'),
    path('users/verification/verified/', VerifiedUserView.as_view(), name='user-verification-verified'),
    path('users/verification/canceled/', CanceledVerifiedUserView.as_view(), name='user-verification-canceled'),
    path('users/verification/pending/', PendingVerifiedUserView.as_view(), name='user-verification-verified'),
    
    
    # KYC verification 
    path('user/kyc-verification/', KYCverificationView.as_view(), name='kyc-verification'),
    path('user/kyc-verification/admin/', KYCverificationAdminView.as_view(), name='kyc-verification-admin'),
    path('user/kyc-verification/<str:pk>/', KYCverificationDeleteView.as_view(), name='kyc-verification'),
    path('user/kyc-verification/<str:pk>/update-status/', KYCverificationStatusUpdateView.as_view(), name='kyc-verification-status'),   
    path('users/without-KYC-verification/', UsersWithoutKYCVerificationView.as_view(), name='users-without-KYCverification'),
    path('users/kyc-verification/verified/', VerifiedKYCView.as_view(), name='user-verification-verified'),
    path('users/kyc-verification/canceled/', CanceledVerifiedKYCView.as_view(), name='user-verification-verified'),
    path('users/kyc-verification/pending/', PendingVerifiedKYCView.as_view(), name='user-verification-pending'),
    
    #User Balance
    path('user/balance/', UserBalanceView.as_view(), name='Balance'),
    path('user/balance/<uuid:user>/', UserBalanceRetriveUpdateDestoryView.as_view(), name='update-Balance'),
    #deposits
    path('deposits/', AllDepositsView.as_view(), name='all-deposits'),
    path('deposits/admin/', depositAdminView.as_view(), name='Admin-deposit'),
    path('deposits/pending/', PendingDepositsView.as_view(), name='pending-deposits'),
    path('deposits/declined/', DeclinedDepositsView.as_view(), name='declined-deposits'),
    path('deposits/successful/', SuccessfulDepositsView.as_view(), name='successful-deposits'),
    path('deposits/<int:pk>/update-status/', DepositStatusUpdateView.as_view(), name='update-deposit-status'),
    path('deposits/<int:pk>/', DepositRetriveDestoryView.as_view(), name='delete-deposit'),
    
    #withdraw
    path('withdraw/', WithdrawView.as_view(), name='all-withdraw'),
    path('withdraw/pending/', PendingWithdrawView.as_view(), name='Pending-withdraw'),
    path('withdraw/declined/', DeclinedWithdrawView.as_view(), name='declined-withdraw'),
    path('withdraw/successful/', SuccessfulWithdrawView.as_view(), name='success-withdraw'),
    path('withdraw/<int:pk>/', WithdrawRetriveDestoryView.as_view(), name='delete-withdraw'),
    path('withdraw/<int:pk>/update-status/', WithdrawStatusUpdateView.as_view(), name='update-withdraw-status'),
    
    # Wallet Address
    path('wallet-address/', WalletAddressView.as_view(), name='wallet-address'), 
    path('wallet-address/<int:pk>/', WalletAddressRetriveUpdateDestoryView.as_view(), name='wallet-address'), 
    path('wallet-address/filter/', FilteredWalletAddress.as_view(), name='wallet-address'),  
    
    #Bank Account
    path('bank-account/', BankAccountView.as_view(), name='bank-account'), 
    path('bank-account/<int:pk>/', BankAccountRetriveUpdateDestoryView.as_view(), name='bank-account'), 
    path('bank-account/filter/', FilteredBankAccount.as_view(), name='bank-account'),
    
    # Bank Card
    path('bank-card/', BankCardView.as_view(), name='bank-card'), 
    path('bank-card/<int:pk>/', BankCardRetriveUpdateDestoryView.as_view(), name='bank-card'), 
    path('bank-card/filter/', FilteredBankCard.as_view(), name='bank-card'),
    
    #payment method
    path('payment-method/', PaymentMethodView.as_view(), name='payment-method'),  
    path('payment-method/<int:id>/', PaymentMethodRetrieveDestoryView.as_view(), name='wallet_qr'),
    
    #Investment Plan
    path('investment-plan/', InvestmentPlanView.as_view(), name='investment-plan'),
    path('investment-plan/<int:id>/', InvestPlanRetrieveDestoryView.as_view(), name='investment-plan'),
    
    #User Investment
    path('user-investment/', UserInvestmentView.as_view(), name='user-investment'),  
    path('user-investment/<int:pk>/', UserInvestmentRetriveUpdateDestoryView.as_view(), name='delete-investment'),
    path('user-investment/successful/', SuccessfulInvestmentView.as_view(), name='sucessful-investment'),  
    path('user-investment/active/', ActiveInvestmentView.as_view(), name='active-investment'),  
    path('user-investment/pending/', PendingInvestmentView.as_view(), name='awaiting-investment'),  
    path('user-investment/completed/', CompletedInvestmentView.as_view(), name='completed-investment'),  
    path('user-investment/declined/', DeclinedInvestmentView.as_view(), name='declined-investment'), 
    path('user-investment/<int:pk>/update-status/', UserInvestmentUpdateStatusView.as_view(), name='status-update-investment'), 
    path('user-investment/<int:pk>/update-type/', UserInvestmentUpdateTypeView.as_view(), name='type-update-investment'), 
    path('user-investment/add-money/', AddMoneyToInvestmentView.as_view(), name='add-money-to-investment'),
    # cash out 
    path('cashout/', CashoutView.as_view(), name='cashout'),  
    # Investment Intrest
    path('investment-intrest/', InvestmentIntrestView.as_view(), name='investment-intrest'), 
    path('investment-intrest/filter/', FilteredInvestmentIntrestView.as_view(), name='investment-intrest'), 
    # Bonus 
    path('bonus/', BonusView.as_view(), name='Bonus'), 
    
    #commission
    path('commission/', CommissionView.as_view(), name='commission'), 
    path('commission/<int:pk>/', CommissionRetrieveDeleteUpdate.as_view(), name='commission-update'),
    path('referral/', ReferralView.as_view(), name='apply_referral'),
    path('user-referral/', UserReferralView.as_view(), name='apply_referral'),
    path('user-commission/', UserCommisionView.as_view(), name='apply_referral'),
    #Account
    path('account/', AccountListView.as_view(), name='account'),
    path('account-details/', AccountDetailsView.as_view(), name='account'),
    
    #Email
    path('send-mail/', SendEmailView.as_view(), name='send-email'),
        path('send-mail/<int:pk>/', sendEmailRetrieveDelete.as_view(), name='send-email'),
    path('list-emails/<str:email_type>/',
         views.ListEmailAddressesAPIView.as_view(), name='list-emails'),
    path('Blacklist-ip/', BlacklistIPView.as_view(), name='blacklist-ip'),
    path('Blacklist-ip/<int:pk>/', BlacklistIPRetrieveDelete.as_view(), name='Blacklist-ip-delete'),
    
    
    path('news-letter/', NewsLetterViews.as_view(), name='news-letter'),
    path('news-letter/<int:pk>/', NewsLetterRetrieveDelete.as_view(), name='news-letter'), 
    
    #Contact Us
    path('contact-us/', ContactUsView.as_view(), name='news-letter'), 
    
    #user profile
    path('user-profile/', UserProfileViews.as_view(), name='user-profile'),
    path('user-profile/<int:pk>/', UserProfileRetrieve.as_view(), name='user-profile'),
    path('user-profile/admin/<uuid:user>/', UserProfileAdminRetrieve.as_view(), name='update-Balance'),
]