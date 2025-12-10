from django.apps import AppConfig
from django.db.utils import OperationalError, ProgrammingError

class BaseConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'base'

    def ready(self):
        import base.signals
        
        # Import inside try-except to avoid errors if the table doesn't exist
        try:
            from django.db import connection
            if 'background_task' in connection.introspection.table_names():
                from .tasks import update_investments
                update_investments(repeat=10*60)  # Schedule every 10 minutes
        except (OperationalError, ProgrammingError):
            pass  # Migrations are not applied yet, so skip scheduling
