from rest_framework import serializers
from .models import User


# Serializer for User Registration

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}
        
    def create(self, validated_data):
        user = User(email=validated_data['email'])
        user.set_password(validated_data['password'])  # Hashing password
        user.save()
        return user

# Verify Account 

class VerifyAccountSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    