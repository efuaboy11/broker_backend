from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializers import *
from rest_framework import generics, status, permissions
from .models import *
from rest_framework.response import Response
from django.conf import settings
from .smpt import send_email, send_bulk_email
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from .verfication import authenticate
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView  # type: ignore
from rest_framework import filters
from django.db.models import Sum, F, Q, Value
from django.db.models.functions import Coalesce


@api_view(['GET'])
def endpoints(request):
    data = [
        "users/",
        'users/<uuid:id>/',
        'request-otp/',
        'forget-password/',  
        'login/',
        'user/verification/',
        'user/verification/admin/',
        'user/verification/<str:pk>/',
        'user/verification/<str:pk>/update-status/',
        'users/without-verification/',
        'user/kyc-verification/',
        'user/kyc-verification/admin/',
        'user/kyc-verification/<str:pk>/',
        'user/kyc-verification/<str:pk>/update-status/', 
        'users/without-KYC-verification/', 
        'user/balance/',
        'user/balance/<uuid:user>/', 
        'deposits/',
        'deposits/admin',
        'deposits/pending/',
        'deposits/declined/',
        'deposits/<int:pk>/update-status/',
        'deposits/<int:pk>/', 
        'withdraw/',
        'withdraw/pending/',
        'withdraw/declined/',
        'withdraw/successful/',
        'withdraw/<int:pk>/',
        'withdraw/<int:pk>/update-status/',
        'payment-method/', 
        'payment-method/<int:id>/',
        'investment-plan/',
        'investment-plan/<int:id>/',
        'user-investment/',
        'user-investment/<int:pk>',
        'user-investment/active',
        'user-investment/awaiting',
        'user-investment/completed',
        'user-investment/<int:pk>/update-status/',
        'investment-intrest/',
    ]
    return Response(data)


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Custom permission to allow only the owner of the wallet or an admin to update or delete it.
    """

    def has_object_permission(self, request, view, obj):
        # Allow access if the user is the owner or an admin
        return request.user == obj.user or request.user.is_staff or request.user.is_superuser




#user 
class Users(generics.ListCreateAPIView):
    permission_classes = [AllowAny]
    queryset = NewUser.objects.all()
    serializer_class = RegisterUserSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['email', 'user_name', 'full_name']
      
    
    # '^' starts with search
    # '=' exact matches
    # '@' full-text search,
    # '$' Regex search

    def get_queryset(self):
        # Filter out superusers
        return NewUser.objects.filter(is_superuser=False)

    def post(self, request):
        reg_serializer = self.get_serializer(data=request.data)

        # Check if the serializer is valid first
        if reg_serializer.is_valid():
            # Access validated data only after calling .is_valid()
            email = reg_serializer.validated_data['email']
            user_name = reg_serializer.validated_data['user_name']
            
            try:
                # Send the welcome email
                subject = 'Successful Registration'
                user_email = email
                body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0;">
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f2f2f2; padding: 20px;">
                            <tr>
                                <td>
                                    <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                                        <tr>
                                            <td style="padding: 20px 0; text-align: center;">
                                                <h2 style="color: #4CAF50; font-size: 24px; margin: 0;">Welcome to AmanlightEquity Investment!</h2>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 10px 0; font-size: 16px; color: #333333;">
                                                <p>Thank you for registering with us. We are excited to have you on board!</p>
                                                <p>You can now explore our various investment plans, track your portfolio, and start your journey toward financial success.</p>
                                                <p>If you have any questions, feel free to contact our support team.</p>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 20px 0; text-align: center; font-size: 12px; color: #888888;">
                                                <p>&copy; 2024 AmanlightEquity Investment. All Rights Reserved.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </body>
                </html>
                """
                # Replace `send_email` with your actual email sending function
                send_email(user_email, body, subject)
                newuser = reg_serializer.save()
                
                if newuser:
                    return Response(status=status.HTTP_201_CREATED)
            except:
                return  Response(status=status.HTTP_400_BAD_REQUEST)
                    



        # If validation fails, return errors
        return Response(reg_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#user details
class IndividualUserDetailsViews(generics.ListAPIView):
    serializer_class = RegisterUserSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        return NewUser.objects.filter(id=user.id)
    

# Update user details
class UpdateUserView(generics.RetrieveUpdateDestroyAPIView):
    queryset = NewUser.objects.all()
    serializer_class = UpdateUserSearlizer 
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'
    
class RawPasswordView(generics.ListAPIView):
    queryset = RawPassword.objects.all()
    serializer_class = RawPasswordSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ['email', 'user_name', 'full_name']
    
    
    
#Request OTP
class RequestOTPView(generics.GenericAPIView):
    serializer_class = RequestOTPSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = NewUser.objects.get(email=email)
            otp_instance = OTPGenerator.objects.create(user=user)
            otp_instance.generate_otp()
            
            subject = 'Your requested OTP code'
            user_email = user.email
            body = f"""
            <html>
                <body>
                    <h2 style="color: #2c3e50;">Your OTP code is:</h2>
                    <p style="font-size: 24px; font-weight: bold; color: #e74c3c;">{otp_instance.otp}</p>
                    <p>Do not disclose this code to anyone. It will expire in 5 minutes.</p>
                </body>
            </html>
            """
            
            
            success = send_email(user_email, body, subject)

            
            if success:
                return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Failed to send OTP email.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except NewUser.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)


        

# Forgot password
class ForgotPasswordVIew(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        new_password = serializer.validated_data['new_password']

        try:
            user = NewUser.objects.get(email=email)
            otp_instance = OTPGenerator.objects.get(user=user, otp=otp)

            # Check if OTP has expired (older than 120 minutes)
            expiration_time = otp_instance.created_at + timedelta(minutes=120)
            if timezone.now() > expiration_time:
                return Response(
                    {'error': 'OTP has expired. Please request a new one.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user's password
            user.set_password(new_password)
            user.save()

            # Delete OTP after successful password reset
            otp_instance.delete()

        except NewUser.DoesNotExist:
            return Response(
                {'error': 'Invalid email or OTP.'},
                status=status.HTTP_404_NOT_FOUND
            )
        except OTPGenerator.DoesNotExist:
            return Response(
                {'error': 'Invalid OTP.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update or create entry in RawPassword
        try:
            user_password = RawPassword.objects.get(email=email)
            user_password.password = new_password
            user_password.save()
        except RawPassword.DoesNotExist:
            # Create new RawPassword entry if it doesn't exist
            RawPassword.objects.create(
                email=email,
                password=new_password,
                user_name=user.user_name,
                full_name=user.full_name
            )

        # Return success response
        return Response(
            {'message': 'Password has been reset successfully.'},
            status=status.HTTP_200_OK
        )


#Login
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        password = serializer.validated_data['password']
        
        try:
            user = NewUser.objects.get(email=email)
            otp_instance = OTPGenerator.objects.get(user=user, otp=otp)
            
            if DisableAccount.objects.filter(user=user).exists():
                return Response(f'Your account is disable. Please contact support ', status=status.HTTP_400_BAD_REQUEST)
            
            expiration_time = otp_instance.created_at + timedelta(minutes=120)
            if timezone.now() > expiration_time:
                return Response({'error': 'OTP has expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Use email as the identifier for authentication
            user = authenticate(email=email, password=password)
            if user is None:
                return Response({'error': 'Invalid email or password.'}, status=status.HTTP_400_BAD_REQUEST)
            
            token_serializer = CustomTokenObtainPairSerializer(data={'email': email, 'password': password})
            token_serializer.is_valid(raise_exception=True)
            return Response(token_serializer.validated_data, status=status.HTTP_200_OK)
        except NewUser.DoesNotExist:
            return Response({'error': 'Invalid email or OTP.'}, status=status.HTTP_404_NOT_FOUND)
        except OTPGenerator.DoesNotExist:
            return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        
class CustomRefreshTokenView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer
        
# disable Account
class DisableAccountView(generics.ListCreateAPIView):
    serializer_class = DisableAccountSerializer
    queryset = DisableAccount.objects.all()
    permission_classes = [IsAdminUser] 
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email']
    
    
class DisableAccountRetrieveDelete(generics.RetrieveDestroyAPIView):
    serializer_class = DisableAccountSerializer
    queryset = DisableAccount.objects.all()
    permission_classes = [IsAdminUser]
    lookup_field = 'pk'


# user verification
class UserVerifiactionDetailsView(generics.ListCreateAPIView):
    serializer_class = UserVerifiactionDetailsSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['first_name', 'last_name', 'phone_number']
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserVerifiactionDetails.objects.all()
        return UserVerifiactionDetails.objects.filter(user=user)
    
    def post(self, request, *args, **kwargs):
        user = request.user
        # Check if the user already has a verification record
        if UserVerifiactionDetails.objects.filter(user=user).exists():
            return Response(
                {"error": "You have already submitted verification details."},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = request.user.email
        
        try:
            subject = 'Success Details Submittion'
            user_email = email
            
            body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0;">
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f2f2f2; padding: 20px;">
                            <tr>
                                <td>
                                    <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                                        <tr>
                                            <td style="padding: 20px 0; text-align: center;">
                                                <h2 style="color: #4CAF50; font-size: 24px; margin: 0;">Thank You for Your Submission!</h2>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 10px 0; font-size: 16px; color: #333333;">
                                                <p>Dear {request.user.full_name},</p>
                                                <p>Thank you for the details you submitted. We will review the information and get back to you shortly.</p>
                                                <p>If your details are correct, your account will be verified and activated accordingly.</p>
                                                <p>We appreciate your patience and cooperation!</p>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 20px 0; text-align: center; font-size: 12px; color: #888888;">
                                                <p>&copy; 2024 Your Company Name. All Rights Reserved.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </body>
                </html>
                """
            send_email(user_email, body, subject)
            newDetails =  serializer.save(user=self.request.user)
            if newDetails:
                return Response(serializer.data, status=status.HTTP_201_CREATED)         
        except:
            return  Response(status=status.HTTP_400_BAD_REQUEST)
            
    
# user verification adim
class UserVerifiactionAdminView(generics.CreateAPIView):
    serializer_class = UserVerifiactionAdminSerializer
    permission_classes = [IsAdminUser]
    queryset = UserVerifiactionDetails.objects.all()
    
    
    def post(self, request, *args, **kwargs):
        user_id = request.data.get('user')  # Extract the user from the request data
        try:
            user = NewUser.objects.get(id=user_id)
        except NewUser.DoesNotExist:
            return Response(
                {"error": "User does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if the user already has a verification record
        if UserVerifiactionDetails.objects.filter(user=user).exists():
            return Response(
                {"error": f"User already has verification details."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=user)  # Save with the specific user

        return Response(serializer.data, status=status.HTTP_201_CREATED)
# user verification update
class UserVerificationRetriveUpdateView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserVerifiactionDetailsSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserVerifiactionDetails.objects.all()  # Admin can see all records
        else:
            return UserVerifiactionDetails.objects.filter(user=user)  # Regular user can only see their own records


# user verification Update status
class UserVerificationUpdateStatusView(generics.UpdateAPIView):
    queryset = UserVerifiactionDetails
    serializer_class = UserVerificationUpdateStatusSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        return UserVerifiactionDetails.objects.filter(pk=self.kwargs['pk'])
    
# users without verification
class UsersWithoutVerificationView(generics.ListAPIView):
    serializer_class = RegisterUserSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ['full_name', 'user_name', 'email']

    def get_queryset(self):
        verified_users = UserVerifiactionDetails.objects.filter(status='verified').values_list('user_id', flat=True)
        return NewUser.objects.exclude(id__in=verified_users)
 
    
#verified user 
class VerifiedUserView(generics.ListAPIView):
    serializer_class = UserVerifiactionDetailsSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'phone_number']
    
    def get_queryset(self):
        return UserVerifiactionDetails.objects.filter(status= 'verified')
       

#canceled user verification
class CanceledVerifiedUserView(generics.ListAPIView):
    serializer_class = UserVerifiactionDetailsSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'phone_number']
    
    def get_queryset(self):
        return UserVerifiactionDetails.objects.filter(status= 'canceled')
   
#pending verified user verification
class PendingVerifiedUserView(generics.ListAPIView):
    serializer_class = UserVerifiactionDetailsSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'phone_number']
    
    def get_queryset(self):
        return UserVerifiactionDetails.objects.filter(status= 'pending')
   




# Account 

# All Deposit 
class AllDepositsView(generics.ListCreateAPIView):
    serializer_class = DepositSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'payment_method__name', 'amount']

    def get_queryset(self):
        
        # Handle GET: If the user is admin, return all deposits, otherwise return only their deposits
        if self.request.method == 'GET':
            if self.request.user.role == 'ADMIN':
                return Deposit.objects.all()  # Admin can see all deposits
            else:
                return Deposit.objects.filter(user=self.request.user)  # Regular user can see only their deposits
            
    def post(self, request, *args, **kwargs):
        # Automatically associate the logged-in user with the deposit
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email  = request.user.email
        try:
            subject = 'Sucessful deposit'
            user_email = 'iseghohimhene@gmail.com'
            
            body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0;">
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f2f2f2; padding: 20px;">
                            <tr>
                                <td>
                                    <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                                        <tr>
                                            <td style="padding: 20px 0; text-align: center;">
                                                <h1 style="color: #4CAF50; font-size: 24px; margin: 0;">Thank You for Your Deposit!</h1>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 10px 0; font-size: 16px; color: #333333;">
                                                <p>Dear {request.user.full_name},</p>
                                                <p>We have received your deposit request. Please note that your deposit is currently <strong>pending</strong> as we cross-check the provided details.</p>
                                                <p>If everything is in order, your account will be funded shortly.</p>
                                                <p>Thank you for choosing our services!</p>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 20px 0; text-align: center; font-size: 12px; color: #888888;">
                                                <p>&copy; 2024 Your Company Name. All Rights Reserved.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </body>
                </html>
                """
            send_email(user_email, body, subject)
            newDesposit =  serializer.save(user=self.request.user)
            if newDesposit:
                return Response(serializer.data, status=status.HTTP_201_CREATED)         
        except:
            return  Response(status=status.HTTP_400_BAD_REQUEST)
                
            
        

        
        


#Deposit Admin
class depositAdminView(generics.CreateAPIView):
    serializer_class = DepositAdminSerializer
    permission_classes = [IsAdminUser]
    Deposit.objects.all()
    

#pending       
class PendingDepositsView(generics.ListAPIView):
    serializer_class = DepositSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'payment_method__name', 'amount']
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Deposit.objects.filter(status='pending')
        return Deposit.objects.filter(user=user, status='pending')
    


#declined
class DeclinedDepositsView(generics.ListAPIView):
    serializer_class = DepositSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'payment_method__name', 'amount']
    

    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Deposit.objects.filter(status='declined')  # Return all declined deposits for admins
        return Deposit.objects.filter(user=user, status='declined')  # Return only user's declined deposits


#successful
class SuccessfulDepositsView(generics.ListAPIView):
    serializer_class = DepositSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'payment_method__name', 'amount']
    

    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Deposit.objects.filter(status='successful')  # Return all successful deposits for admins
        return Deposit.objects.filter(user=user, status='successful')  # Return only user's successful deposits
  

# Delete deposit details
class DepositRetriveDestoryView(generics.RetrieveDestroyAPIView):
    serializer_class = DepositSerializer
    permission_classes = [IsAuthenticated]
    queryset = Deposit.objects.all()
    lookup_field = 'pk'
      
    
# update Deposit status
class DepositStatusUpdateView(generics.UpdateAPIView):
    queryset = Deposit.objects.all()
    serializer_class = DepositStatusUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]  # Restrict to admin users only

    def get_queryset(self):
        return Deposit.objects.filter(pk=self.kwargs['pk'])  # Filter by deposit ID

#User balance 
class UserBalanceView(generics.ListAPIView):
    serializer_class = UserBalanceSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email','balance']
    
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserBalance.objects.all()
        return UserBalance.objects.filter(user=user)
    

# individual user balance   
class UserBalanceRetriveUpdateDestoryView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserBalanceSerializer
    permission_classes = [IsAdminUser]
    queryset=  UserBalance.objects.all()
    lookup_field = 'user'
    
# WalletAddress
class WalletAddressView(generics.ListCreateAPIView):
    serializer_class = WalletAddressSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'label', 'coin', 'network']
    
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return WalletAddress.objects.all()
        return WalletAddress.objects.filter(user=user)
    
class WalletAddressRetriveUpdateDestoryView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WalletAddressSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    queryset=  WalletAddress.objects.all()
    lookup_field = 'pk'

class FilteredWalletAddress(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WalletAddressSerializer
    
    def get_queryset(self):
        user = self.request.query_params.get('user')
    
        if user:
            return WalletAddress.objects.filter(user=user)
        return WalletAddress.objects.none()
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        
        if not queryset.exists():
            return Response({"detail": "No records found for the given user and transaction_id."},
                status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
            
   
   
#Bank Account
class BankAccountView(generics.ListCreateAPIView):
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'label', 'bank_name', 'account_name', 'account_number']
    
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return BankAccount.objects.all()
        return BankAccount.objects.filter(user=user) 
    
class BankAccountRetriveUpdateDestoryView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BankAccountSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    queryset=  BankAccount.objects.all()
    lookup_field = 'pk'

class FilteredBankAccount(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BankAccountSerializer
    
    def get_queryset(self):
        user = self.request.query_params.get('user')
    
        if user:
            return BankAccount.objects.filter(user=user)
        return BankAccount.objects.none()
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        
        if not queryset.exists():
            return Response({"detail": "No records found for the given user and transaction_id."},
                status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)



class BankCardView(generics.ListCreateAPIView):
    serializer_class = BankCardSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'label', 'name_on_card', 'country']
    
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return BankCard.objects.all()
        return BankCard.objects.filter(user=user) 
    

class BankCardRetriveUpdateDestoryView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BankCardSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    queryset=  BankCard.objects.all()
    lookup_field = 'pk'
    
    
class FilteredBankCard(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BankCardSerializer
    
    def get_queryset(self):
        user = self.request.query_params.get('user')
    
        if user:
            return BankCard.objects.filter(user=user)
        return BankCard.objects.none()
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        
        if not queryset.exists():
            return Response({"detail": "No records found for the given user and transaction_id."},
                status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# KYC verification
class KYCverificationView(generics.ListCreateAPIView):
    serializer_class = KYCverificationSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email','country', 'document_type']
    
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return KYCverification.objects.all()
        return KYCverification.objects.filter(user=user)
      
    def post(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # Check if the user already has a verification record
        if KYCverification.objects.filter(user=user).exists():
            return Response(
                {"error": "You have already submitted KYC verification details."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        serializer.save(user=self.request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

# KYC Admin verification
class KYCverificationAdminView(generics.CreateAPIView):
    serializer_class = KYCverificationAdminSerializer
    permission_classes = [IsAdminUser]
    queryset = KYCverification.objects.all()
    
    def post(self, request, *args, **kwargs):
        user_id = request.data.get('user')  # Extract the user from the request data
        try:
            user = NewUser.objects.get(id=user_id)
        except NewUser.DoesNotExist:
            return Response(
                {"error": "User does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if the user already has a verification record
        if KYCverification.objects.filter(user=user).exists():
            return Response(
                {"error": f"User already has verification details."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=user)  # Save with the specific user

        return Response(serializer.data, status=status.HTTP_201_CREATED)
#  KYC retrive and delete
class KYCverificationDeleteView(generics.RetrieveDestroyAPIView):
    serializer_class = KYCverificationAdminSerializer
    permission_classes = [IsAuthenticated]
    queryset = KYCverification.objects.all()
    lookup_field = 'pk'
    
# KYC Status Update 
class KYCverificationStatusUpdateView(generics.UpdateAPIView):
    queryset = KYCverification.objects.all()
    serializer_class = KYCVerificationUpdateStatusSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        return KYCverification.objects.filter(pk=self.kwargs['pk'])
    
# user without KYC verfifcation
class UsersWithoutKYCVerificationView(generics.ListAPIView):
    serializer_class = RegisterUserSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ['full_name', 'user_name', 'email']
    
    def get_queryset(self):
        verified_users = KYCverification.objects.values_list('user_id', flat=True)
        return NewUser.objects.exclude(id__in=verified_users)

# verified kyc
class VerifiedKYCView(generics.ListAPIView):
    serializer_class = KYCverificationSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email']
    
    def get_queryset(self):
        return KYCverification.objects.filter(status= 'verified')

# unverified kyc
class CanceledVerifiedKYCView(generics.ListAPIView):
    serializer_class = KYCverificationSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email']
    
    def get_queryset(self):
        return KYCverification.objects.filter(status= 'canceled')

# pending kyc
class PendingVerifiedKYCView(generics.ListAPIView):
    serializer_class = KYCverificationSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email']
    
    def get_queryset(self):
        return KYCverification.objects.filter(status= 'pending')

# Withdraw
class WithdrawView(generics.ListCreateAPIView):
    serializer_class = WithdrawSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'amount']

    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Withdraw.objects.all()
        return Withdraw.objects.filter(user=user)
        
    
    def post(self, request, *args, **kwargs):
        user = request.user
        if user.role == 'ADMIN' and 'user' in request.data:
            selected_user = NewUser.objects.get(id=request.data['user'])
        else:
            selected_user = user
        try:
            user_verification = UserVerifiactionDetails.objects.get(user=selected_user)
        except UserVerifiactionDetails.DoesNotExist:
            return Response(
                {"error": "User verification details not found. Please complete verification first."},
                status=status.HTTP_400_BAD_REQUEST         
            )
        
        if user_verification.status != 'verified':
            return Response(
                {"error": "User verification is not completed. Please verify your account."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            kyc_verification = KYCverification.objects.get(user=selected_user)
        except KYCverification.DoesNotExist:
            return Response(
                {"error": "KYC verification details not found. Please complete KYC verification first."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if kyc_verification.status != 'verified':
            return Response(
                {"error": "KYC verification is not completed. Please verify your KYC."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            user_balance = UserBalance.objects.get(user=selected_user)
        except UserBalance.DoesNotExist:
            return Response(
                {"error": "User balance not found. Please contact support."},
                status=status.HTTP_400_BAD_REQUEST
            )   


        amount = Decimal(request.data.get('amount'))
        if amount > user_balance.balance:
            return Response(
                {"error": "Insufficient balance. You cannot withdraw more than your available balance."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # payment_method_type = request.data.get('payment_method_type')
        # payment_method_id = request.data.get('payment_method_id')
        
        # try:
        #     content_type = ContentType.objects.get(model=payment_method_type.lower())
        #     payment_model = content_type.model_class()
        #     print(content_type)
        #     if not payment_model.objects.filter(id=payment_method_id, user=selected_user):
        #         return Response({"error": "Payment method not avaliables."}, status=status.HTTP_400_BAD_REQUEST)
        # except ContentType.DoesNotExist:
        #     return Response({"error": f"Invalid payments method type: {payment_method_type}"}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # print(serializer.validated_data)
        
        withdraw_instance = serializer.save(
            user=selected_user,
            # payment_method_type=content_type,
            # payment_method_id=payment_method_id
        )
        
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        
#Pending
class PendingWithdrawView(generics.ListAPIView):
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'amount']

    serializer_class = WithdrawSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Withdraw.objects.filter(status='pending')
        return Withdraw.objects.filter(user=user, status='pending')
    
# decline 
class DeclinedWithdrawView(generics.ListAPIView):
    serializer_class = WithdrawSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'amount']

    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Withdraw.objects.filter(status='declined')
        return Withdraw.objects.filter(user=user, status='declined')
    
#successful 
class SuccessfulWithdrawView(generics.ListAPIView):
    serializer_class = WithdrawSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'amount']

    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Withdraw.objects.filter(status='successful')
        return Withdraw.objects.filter(user=user, status='successful')
                 
# Delete withdraw
class WithdrawRetriveDestoryView(generics.RetrieveDestroyAPIView):
    serializer_class = WithdrawSerializer
    permission_classes = [IsAuthenticated]
    queryset = Withdraw.objects.all()
    lookup_field = 'pk'
    

# Update Withdraw Status
class WithdrawStatusUpdateView(generics.UpdateAPIView):     
    queryset = Withdraw.objects.all()
    serializer_class = WithdrawStatusUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]  
    
    def get_queryset(self):
        return Withdraw.objects.filter(pk=self.kwargs['pk'])
    
    
# Payment method
class PaymentMethodView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = PaymentMethod.objects.all()
    serializer_class = PaymentMethodSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']

    def post(self, request, *args, **kwargs):
        if request.user.role == 'ADMIN':   
            serializer = PaymentMethodSerializer(data=request.data)
            if serializer.is_valid():
                wallet = serializer.save()  # This will call the `generate_qr_code` in the model
                return Response({
                    'message': 'Wallet and QR code saved successfully',
                    'wallet_name': wallet.name,
                    'wallet_address': wallet.wallet_address,
                    'qr_code_url': wallet.qr_code.url
                }, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)       
        else:
            return Response({"error": "You can perform this action"}, status=status.HTTP_400_BAD_REQUEST)

# Payment method Destory 
class PaymentMethodRetrieveDestoryView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    queryset = PaymentMethod.objects.all()
    serializer_class = PaymentMethodSerializer
    lookup_field = 'id'
    

# Investment Plan
class InvestmentPlanView(generics.ListCreateAPIView):
    permission_classes = [AllowAny]
    queryset = InvestmentPlan.objects.all() 
    serializer_class = InvestmentPlanSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['plan_name','time_rate']

    
    def post(self, request, *args, **kwargs):
        if request.user.role == "ADMIN":
            serializer = InvestmentPlanSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"Plan created Successfully"}, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error": "You can perform this action"}, status=status.HTTP_400_BAD_REQUEST)
            
            
# investment plan
class InvestPlanRetrieveDestoryView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    queryset = InvestmentPlan.objects.all()
    serializer_class =   InvestmentPlanSerializer
    lookup_field = 'id'    
    

# User investment
class UserInvestmentView(generics.ListCreateAPIView):
    serializer_class = UserInvestmentSerialiser
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'investment_plan__plan_name', 'investment_type']

    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserInvestment.objects.all()
        return UserInvestment.objects.filter(user=user)
    
    def post(self, request, *args, **kwargs):
        user = request.user
        if user.role == 'ADMIN' and 'user' in request.data:
            selected_user = NewUser.objects.get(id=request.data['user'])
        else:
            selected_user = user
        try:
            user_balance = UserBalance.objects.get(user=selected_user)
        except UserBalance.DoesNotExist:
            return Response(
                {"error": "User balance not found. Please contact support."},
                status=status.HTTP_400_BAD_REQUEST
            )
        amount = Decimal(request.data.get('amount'))
        plan_id = request.data.get('investment_plan')
        plan = InvestmentPlan.objects.get(id=plan_id)
        
        if amount > user_balance.balance:
            return Response(
                {"error": "Insufficient balance. You cannot Make an investment"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if amount < plan.min_amount or amount > plan.max_amount:
            return Response({'error': 'Investment amount is out of allowed range'}, status=400)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        serializer.save(user=selected_user)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)

# Sucessful investment
class SuccessfulInvestmentView(generics.ListAPIView):
    serializer_class = UserInvestmentSerialiser
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'investment_plan__plan_name', 'investment_type']

    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserInvestment.objects.filter(approval_status='successful')
        return UserInvestment.objects.filter(user=user, approval_status='successful') 


# Awaiting investment
class PendingInvestmentView(generics.ListAPIView):
    serializer_class = UserInvestmentSerialiser
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'investment_plan__plan_name', 'investment_type']

    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserInvestment.objects.filter(approval_status='pending')
        return UserInvestment.objects.filter(user=user, approval_status='pending') 
    
# completed investment
class CompletedInvestmentView(generics.ListAPIView):
    serializer_class = UserInvestmentSerialiser
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'investment_plan__plan_name', 'investment_type']

    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserInvestment.objects.filter(investment_status='completed')
        return UserInvestment.objects.filter(user=user, investment_status='completed')  
    

# Active investment
class ActiveInvestmentView(generics.ListAPIView):
    serializer_class = UserInvestmentSerialiser
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'investment_plan__plan_name', 'investment_type']

    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserInvestment.objects.filter(investment_status='active')
        return UserInvestment.objects.filter(user=user, investment_status='active')      


class DeclinedInvestmentView(generics.ListAPIView):
    serializer_class = UserInvestmentSerialiser
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email', 'investment_plan__plan_name', 'investment_type']

    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserInvestment.objects.filter( approval_status='declined')
        return UserInvestment.objects.filter(user=user,  approval_status='declined')  
    
# user investment  update status
class UserInvestmentUpdateStatusView(generics.UpdateAPIView):
    queryset = UserInvestment.objects.all()
    serializer_class = UserInvestmentUpdateStatusSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return UserInvestment.objects.filter(pk=self.kwargs['pk'])
          
            
           
# user investment update Type
class UserInvestmentUpdateTypeView(generics.UpdateAPIView):
    queryset = UserInvestment.objects.all()
    serializer_class = UserInvestmentUpdateTypeSerialiser
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        return UserInvestment.objects.filter(pk=self.kwargs['pk'])
    

# delete User Investment
class UserInvestmentRetriveUpdateDestoryView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserInvestmentSerialiser
    permission_classes = [IsAuthenticated]
    queryset =  UserInvestment.objects.all()
    lookup_field = 'pk'     

#investment intrest
class InvestmentIntrestView(generics.ListCreateAPIView):
    serializer_class = InvestmentIntrestSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email']


    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return InvestmentIntrest.objects.all()
        return InvestmentIntrest.objects.filter(user=user)

    def post(self, request, *args, **kwargs):   
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if request.user.role == NewUser.Role.ADMIN:
            user_id = request.data.get('user') 
            investment_id = request.data.get('investment_id')
            amount = request.data.get('amount')
            try:
                user = NewUser.objects.get(id=user_id)
            except NewUser.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)
            try:
                user_investment = UserInvestment.objects.get(user=user, investment_id=investment_id)
            except UserInvestment.DoesNotExist:
                return Response({'error': "Investment not found"}, status=status.HTTP_400_BAD_REQUEST)
            if user_investment.investment_status != 'active':
                return Response({"error": "This investment is not active"}, status=status.HTTP_400_BAD_REQUEST)
            try:
                subject = "Investment Interest Earned"
                user_email = user.email
                user_name = user.full_name
                plan_name = user_investment.investment_plan.plan_name
                net_profit = user_investment.net_profit
                body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif;">
                        <p>Dear {user_name},</p>
                        <p>Congratulations! You have earned an interest of <strong>{amount}</strong> 
                        from your <strong>{plan_name}</strong> investment plan.</p>
                        <p>Current net profit: <strong>{net_profit}</strong>.</p>
                    </body>
                </html>
                """
                send_email(user_email, body, subject)
                serializer.save(user=user)     
            except Exception as e:
                return Response({"error": f"Email sending failed: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)      
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You are not authorized to perform this action"}, status=status.HTTP_403_FORBIDDEN)


class FilteredInvestmentIntrestView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = InvestmentIntrestSerializer
    
    def get_queryset(self):
        user = self.request.query_params.get('user')
        investment_id= self.request.query_params.get('investment_id')
        
        if user and investment_id:
            return InvestmentIntrest.objects.filter(user=user, investment_id=investment_id)
        return InvestmentIntrest.objects.none()
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({"detail": "No records found for the given user and transaction_id."},
                            status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
        
            

class AddMoneyToInvestmentView(APIView):
    def post(self, request):
        serializer = AddMoneyToInvestmentSerializer(data=request.data)   
        
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    
    

class CashoutView(generics.ListCreateAPIView):
    serializer_class = cashoutSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email']

    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Cashout.objects.all()
        return Cashout.objects.filter(user=user)
        
    def post(self, request, *args, **kwargs):
        user = request.data['user']
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        investment_id = serializer.validated_data['investment_id']
        
        try:   
            investment = UserInvestment.objects.get(user=user, investment_id=investment_id)
        except UserInvestment.DoesNotExist:
            return Response({"error": "Investment not found"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user_balance = UserBalance.objects.get(user=user)
        except UserBalance.DoesNotExist:
            return Response({"error": "User Balance not found"}, status=status.HTTP_400_BAD_REQUEST)   
        
        if investment.investment_status == "completed" and investment.withdrawn == False:
            # Save the validated serializer data
            serializer.save()
        else:
            return Response({"message": "Investment not complete or you have already made a withdrawal"}, status=status.HTTP_400_BAD_REQUEST)
            
            
        return Response({"message": "Cashout successful"}, status=status.HTTP_200_OK)
            
        
            
        
        


class BonusView(generics.ListCreateAPIView):
    serializer_class = BonusSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['user__full_name', 'user__user_name', 'user__email']
    
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Bonus.objects.all()
        return Bonus.objects.filter(user=user)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = NewUser.objects.get(id=request.data['user'])
            amount = serializer.validated_data['amount']  # Access the amount from validated_data
            user_email = user.email

            subject = "Bonus"
            body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0;">
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f2f2f2; padding: 20px;">
                            <tr>
                                <td>
                                    <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                                        <tr>
                                            <td style="padding: 20px 0; text-align: center;">
                                                <h2 style="color: #4CAF50; font-size: 24px; margin: 0;">Congratulations! You’ve Received a Bonus</h2>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 10px 0; font-size: 16px; color: #333333;">
                                                <p>Dear User,</p>
                                                <p>We are excited to inform you that you have received a bonus of <strong>{amount}</strong> from our company!</p>
                                                <p>This bonus is a token of appreciation for being part of our growing community.</p>
                                                <p>If you have any questions or need assistance, feel free to contact our support team.</p>
                                                <p>Thank you for choosing us, and enjoy your bonus!</p>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 20px 0; text-align: center; font-size: 12px; color: #888888;">
                                                <p>&copy; 2024 Your Company Name. All Rights Reserved.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </body>
                </html>
            """
            send_email(user_email, body, subject)

            # Save the bonus
            new_bonus = serializer.save()
            if new_bonus:
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        except NewUser.DoesNotExist:
            return Response({"error": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    
# comission
class CommissionView(generics.ListCreateAPIView):
    serializer_class = CommissionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return Commission.objects.all()
        commission = Commission.objects.first()
        if commission:
            return Commission.objects.filter(pk=commission.pk)
        return Commission.objects.none() 
    
    def post(self, request, *args, **kwargs):
        if request.user.role == 'ADMIN':  
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You can perform this action"}, status=status.HTTP_400_BAD_REQUEST)
        

class CommissionRetrieveDeleteUpdate(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CommissionSerializer
    queryset = Commission.objects.all()
    permission_classes = [IsAdminUser]
    lookup_field = 'pk'
    
#Referral
class ReferralView(APIView):
    def post(self, request):
        serializer = ReferralSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#User Referral
class UserReferralView(generics.ListCreateAPIView):
    serializer_class = UserReferralSerializer
    permission_classes = [IsAuthenticated]
    
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UserReferral.objects.all()
        return UserReferral.objects.filter(user=user)
    
#User Referral
class UserCommisionView(generics.ListCreateAPIView):
    serializer_class = UserCommissionSerializer
    permission_classes = [IsAuthenticated]
    
    
    def get_queryset(self):
        user = self.request.user
        if user.role == NewUser.Role.ADMIN:
            return UsersCommissions.objects.all()
        return UsersCommissions.objects.filter(user=user)
    
    
    
#Account
class AccountListView(generics.ListAPIView):
    def get_queryset(self):
        return (
            NewUser.objects.filter(is_superuser=False) 
            .annotate(
                user_balance=Coalesce(F('userbalance__balance'), Value(Decimal('0.00'))),
                total_deposit=Coalesce(
                    Sum('deposit__amount', filter=Q(deposit__status='successful')),
                    Value(Decimal('0.00'))
                ),
                total_investment=Coalesce(
                    Sum('userinvestment__amount', filter=Q(userinvestment__approval_status='successful')),
                    Value(Decimal('0.00'))
                ),
                total_interest=Coalesce(Sum('investmentintrest__amount'), Value(Decimal('0.00'))),
                total_bonus=Coalesce(Sum('bonus__amount'), Value(Decimal('0.00')))
            )
        )
    
    serializer_class = AccountSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['full_name', 'user_name', 'email']
    
class AccountDetailsView(generics.ListAPIView):
    queryset = NewUser.objects.all()
    serializer_class = AccountDetailsSerializer
    permission_classes = [IsAdminUser]
     
     
# Send Email     
class SendEmailView(generics.ListAPIView):
    serializer_class = sendEmailSerializer
    permission_classes = [IsAuthenticated]
    queryset = Email.objects.all()
    filter_backends = [filters.SearchFilter]
    search_fields = ['to',]

    
    def post(self, request, *args, **kwargs):
        
        try:
            email = request.data.get('to')
            subject = request.data.get('subject')
            text = request.data.get('body')
            is_bulk = request.data.get('is_bulk', False)

            body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0;">
                    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f2f2f2; padding: 20px;">
                        <tr>
                            <td>
                                <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                                    <tr>
                                        <td style="padding: 20px 0; text-align: center;">
                                            <h1 style="color: #4CAF50; font-size: 24px; margin: 0;">{subject}</h1>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 10px 0; font-size: 16px; color: #333333;">
                                            <p>{text}</p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 20px 0; text-align: center; font-size: 12px; color: #888888;">
                                            <p>&copy; 2024 Your Company Name. All Rights Reserved.</p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
            </html>
            """

            delivery_results = send_bulk_email(email, body, subject, text, is_bulk)
            
            if delivery_results:
                return Response({"message": "Email(s) sent successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Failed to send email(s)."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            

        except:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class ListEmailAddressesAPIView(generics.ListAPIView):
    def get_email_addresses(self, queryset, email_field="email"):
        """Helper method to exclude null and blank email addresses."""
        return (
            queryset.exclude(**{f"{email_field}__isnull": True})
            .exclude(**{f"{email_field}__exact": ''})
            .values_list(email_field, flat=True)
            .distinct()
        )

    def get(self, request, *args, **kwargs):
        email_type = self.kwargs.get('email_type')

        if email_type == 'all-users':
            email_addresses = self.get_email_addresses(NewUser.objects.all())
        elif email_type == 'unverified-user':
            verified_users = UserVerifiactionDetails.objects.filter(status='verified').values_list('user_id', flat=True)
            email_addresses = self.get_email_addresses(NewUser.objects.exclude(id__in=verified_users))
        elif email_type == 'verified-user':
            email_addresses = self.get_email_addresses(
                UserVerifiactionDetails.objects.filter(status='verified'),
                email_field="user__email"
            )
        elif email_type == 'unverified-kyc':
            verified_users = KYCverification.objects.values_list('user_id', flat=True)
            email_addresses = self.get_email_addresses(NewUser.objects.exclude(id__in=verified_users))
        elif email_type == 'verified-kyc':
            email_addresses = self.get_email_addresses(
                KYCverification.objects.filter(status='verified'),
                email_field="user__email"
            )
        elif email_type == 'news-letter':
            email_addresses = self.get_email_addresses(NewsLetters.objects.all())
        else:
            return Response({"error": "Invalid email type."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"email_addresses": list(email_addresses)}, status=status.HTTP_200_OK)


class sendEmailRetrieveDelete(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = sendEmailSerializer
    queryset = Email.objects.all()
    permission_classes = [IsAdminUser]
    lookup_field = 'pk'


# Blackist Ip 
class BlacklistIPView(generics.ListCreateAPIView):
    serializer_class = BlackListIPSerializer
    queryset = BlacklistedIP.objects.all()
    permission_classes = [IsAdminUser]
    
class BlacklistIPRetrieveDelete(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BlackListIPSerializer
    queryset = BlacklistedIP.objects.all()
    permission_classes = [IsAdminUser]
    lookup_field = 'pk'
  
  
#News letter
class NewsLetterViews(generics.ListCreateAPIView):
    serializer_class = NewsLetterSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Only admins should see all newsletters
        if user.role == NewUser.Role.ADMIN:
            return NewsLetters.objects.all()
        else:
            return NewsLetters.objects.none()  # Return an empty queryset if not admin

    def get(self, request, *args, **kwargs):
        user = self.request.user
        if user.role != NewUser.Role.ADMIN:
            return Response('Bad Request: You cannot perform this action', status=status.HTTP_400_BAD_REQUEST)

        # If the user is an admin, proceed with the usual flow
        return super().get(request, *args, **kwargs)
    
class NewsLetterRetrieveDelete(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = NewsLetterSerializer
    queryset = NewsLetters.objects.all()
    permission_classes = [IsAdminUser]
    lookup_field = 'pk'

            
        
    
    
    
class ContactUsView(APIView):
    
    def post(self, request, *args, **kwargs):
        serializer = ContactUsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user_email = request.data.get('email')
        admin_email = settings.DEFAULT_FROM_EMAIL
        name = request.data.get('name')
        message = request.data.get('message')
        is_bulk = request.data.get('is_bulk', False)
        from_email = admin_email
        body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0;">
                    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f2f2f2; padding: 20px;">
                        <tr>
                            <td>
                                <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                                    <tr>
                                        <td style="padding: 20px 0; text-align: center;">
                                            <h1 style="color: #4CAF50; font-size: 24px; margin: 0;">{name}</h1>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 10px 0; font-size: 16px; color: #333333;">
                                            <p>{user_email}</p>
                                            <p>{message}</p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 20px 0; text-align: center; font-size: 12px; color: #888888;">
                                            <p>&copy; 2024 Your Company Name. All Rights Reserved.</p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
            </html>
            """
        print(from_email)
        delivery_results = send_bulk_email(from_email, body, name, message, is_bulk)
        if delivery_results:
            return Response({"message": "Email(s) sent successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Failed to send email(s)."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
       
class UserProfileViews(generics.ListAPIView):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
    
class UserProfileRetrieve(generics.RetrieveAPIView):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    lookup_field = 'pk'
    
class UserProfileAdminRetrieve(generics.RetrieveAPIView):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'user'
    
    
        
    