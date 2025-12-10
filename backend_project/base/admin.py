from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(NewUser)
admin.site.register(Deposit)
admin.site.register(UserBalance)
admin.site.register(UserVerifiactionDetails)
admin.site.register(KYCverification)
admin.site.register(UserInvestment)
admin.site.register(Withdraw)
admin.site.register(InvestmentIntrest)
admin.site.register(InvestmentPlan)
admin.site.register(RawPassword)
admin.site.register(UserProfile)

