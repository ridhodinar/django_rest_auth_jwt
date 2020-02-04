from rest_framework import serializers
from .models import Account

def password_min_length(value):
    if len(value) <= 8:
        raise serializers.ValidationError('password must have 8 characters')

def password_match(value1, value2):
    if value1 != value2:
        raise serializers.ValidationError({'detail':'password did not match'})