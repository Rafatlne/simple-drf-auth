from dataclasses import fields
from pyexpat import model
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.authtoken.models import Token

User = get_user_model()


class BaseUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "email",
            "is_staff",
            "is_active",
            "groups",
            "created_at",
            "updated_at",
            "user_type"
        )
        extra_kwargs = {
            'groups': {'required': True},
        }
        
        
class UserCreateTokenSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, style={"input_type": "password"})


class TokenSerializer(serializers.ModelSerializer):
    auth_token = serializers.CharField(source="key")

    class Meta:
        model = Token
        fields = ("auth_token",)
        
        
class BaseUserCreatePasswordRetypeSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True, style={"input_type": "password"})
    re_type_password = serializers.CharField(required=True, style={"input_type": "password"})

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "email",
            "password",
            "re_type_password",
        )
        

class BaseUserActivationSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    

class BaseUserPasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True, style={"input_type": "password"})
    new_password = serializers.CharField(required=True, style={"input_type": "password"})
    re_type_new_password = serializers.CharField(required=True, style={"input_type": "password"})
    
    
class BaseUserPasswordForgotSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    
    
class BaseUserPasswordForgotActivationSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    password = serializers.CharField(required=True, style={"input_type": "password"})
    re_type_password = serializers.CharField(required=True, style={"input_type": "password"})