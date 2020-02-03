from rest_framework import serializers
from .models import Account
class RegisterSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Account
        fields = ['username','email','password'] 
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        account = Account(
            email=validated_data['email'],
            username=validated_data['username']
        )
        account.set_password(validated_data['password'])
        account .is_active = False
        account.save()
        return account