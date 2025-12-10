from background_task import background
from django.utils import timezone
from decimal import Decimal
from .models import UserInvestment, InvestmentIntrest

# Run every 10 minutes, and check if an update is needed for all time rates
@background(schedule=10*60)  # run every 10 minutes
def update_investments():
    now = timezone.now()

    # Fetch all automatic investments that are active
    investments = UserInvestment.objects.filter(investment_status='active', investment_type='automatic')

    for investment in investments:
        last_update = investment.last_update_time or investment.investment_begins
        
        # Hourly check
        if investment.investment_time_rate == 'hourly' and (now - last_update).total_seconds() >= 3600:  # 1 hour
            add_return_profit(investment)
            investment.last_update_time = now
            investment.save()

        # Daily check
        elif investment.investment_time_rate == 'daily' and (now - last_update).days >= 1:  # 1 day
            add_return_profit(investment)
            investment.last_update_time = now
            investment.save()

        # Weekly check
        elif investment.investment_time_rate == 'weekly' and (now - last_update).days >= 7:  # 7 days
            add_return_profit(investment)
            investment.last_update_time = now
            investment.save()

        # Monthly check (approximate, 30 days)
        elif investment.investment_time_rate == 'monthly' and (now - last_update).days >= 30:  # 30 days
            add_return_profit(investment)
            investment.last_update_time = now
            investment.save()

# Helper function to add the profit
def add_return_profit(investment):
    return_profit = investment.return_profit
    investment.current_intrest_return = Decimal(investment.current_intrest_return) + return_profit
    
    # Log interest in the InvestmentIntrest table
    InvestmentIntrest.objects.create(
        user=investment.user,
        investment_id=investment.investment_id,    
        amount=return_profit
    )
    
    # Save investment details after updating the interest
    investment.save()

    # Check if the investment has reached its net profit, then complete it
    if investment.current_intrest_return >= investment.net_profit:
        investment.investment_status = 'completed'
        investment.investment_ends = timezone.now()
        investment.save()
