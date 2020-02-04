from rest_framework import serializers
from .models import Account
from rest_framework.validators import UniqueValidator
from .validators import *

class RegisterSerializer(serializers.ModelSerializer):
    
    username = serializers.CharField(validators=[UniqueValidator(queryset=Account.objects.all())])
    email = serializers.EmailField(validators=[UniqueValidator(queryset=Account.objects.all())])
    password = serializers.CharField(validators=[password_min_length])
    password2 = serializers.CharField(validators=[password_min_length])

    class Meta:
        model = Account
        fields = ['username','email','password','password2'] 
        extra_kwargs = {'password2': {'write_only': True}}

    def create(self, validated_data):
        account = Account(
            email=validated_data['email'],
            username=validated_data['username']
        )

        password_match(validated_data['password'], validated_data['password2'])

        account.set_password(validated_data['password'])
        account .is_active = False
        account.save()
        return account

class ChangePasswordSerializer(serializers.Serializer):
    password1 = serializers.CharField(validators=[password_min_length])
    password2 = serializers.CharField(validators=[password_min_length])

    def validate(self, attrs):
        password_match(attrs['password1'], attrs['password2'])
        return attrs

class ActivaAccountSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    
    def validate(self, attrs):
        data = {}

        data['uid'] = attrs['uid']
        data['token'] = attrs['token']
        
        return data

class ResetPasswordConfirmSerializer(ChangePasswordSerializer, ActivaAccountSerializer):
    pass



