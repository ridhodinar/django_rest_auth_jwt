from rest_framework import serializers
from .models import Account

class RegisterSerializer(serializers.ModelSerializer):
    
    password2 = serializers.CharField(max_length=None, min_length=None, allow_blank=False)

    class Meta:
        model = Account
        fields = ['username','email','password','password2'] 
        extra_kwargs = {'password2': {'write_only': True}}

    def create(self, validated_data):
        account = Account(
            email=validated_data['email'],
            username=validated_data['username']
        )
        if validated_data['password'] == validated_data['password2']:
            account.set_password(validated_data['password'])
            account .is_active = False
            account.save()
            return account
        else: 
            raise serializers.ValidationError({'detail':'passwords did not match'})