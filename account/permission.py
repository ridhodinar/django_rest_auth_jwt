from rest_framework.permissions import BasePermission
from .models import Account

class APILoginPermission(BasePermission):
    
    def has_permission(self, request, view):
        account = Account.objects.get(username=request.data['username'])
        return account.is_active

