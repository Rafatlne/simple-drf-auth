from django.contrib.auth import get_user_model, authenticate
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import APIException, ValidationError
from django.http import Http404
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.contrib.auth.tokens import default_token_generator
from .helper import encode_uid, decode_uid

User = get_user_model()

class BaseUserValidationService:
    model_class = User
    
    def check_user_authentication(self, request):
        password = request.get("password")
        params = {"email": request.get("email")}
        
        user = authenticate(
            request=request, **params, password=password
        )
        if not user:
            user = self.model_class.objects.filter(**params).first()
            if user and not user.check_password(password):
                raise APIException(detail="Unable to log in with provided credentials.", code=status.HTTP_201_CREATED)
        
        if not user or not user.is_active:
            raise APIException(detail="Unable to log in with provided credentials.", code=status.HTTP_201_CREATED)
        
        return user
    
    def validate_password(self, user, password):
        try:
            validate_password(password, user)
        except DjangoValidationError as e:
            raise APIException(detail=e.messages[0])
        
    
    def validate_password_with_retype_password(self, password, re_type_password):
        if password != re_type_password:
            raise APIException(detail="Password and retype password must be same.", code=status.HTTP_201_CREATED)
        
    def get_user_from_validated_uid(self, validated_data):
        try:
            uid = decode_uid(validated_data.get("uid", ""))
            user = User.objects.get(pk=uid)
            
            return user
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            key_error = "invalid_uid"
            raise ValidationError(
                {"uid": "Invalid user id or user doesn't exist."}, code=key_error
            )
            
    def validate_activation_token(self, user, validated_data):

        is_token_valid = default_token_generator.check_token(
            user, validated_data.get("token", "")
        )
        if not is_token_valid:
            key_error = "invalid_token"
            raise ValidationError(
                {"token": "Invalid token for given user."}, code=key_error
            )
            
    def validate_current_password(self, user, validated_data, **kwargs):
        is_password_valid  = user.check_password(validated_data.get('current_password', ""))
        
        if not is_password_valid:
            key_error = "invalid_password"
            raise APIException({"password": "Invalid password."}, code=key_error)


class TokenCreateService:
    model_class = Token
    base_user_validation_service = BaseUserValidationService()
    
    def create(self, request):
        user = self.base_user_validation_service.check_user_authentication(request)
        token, _ = Token.objects.get_or_create(user=user)
        return token
    
    def get_activation_token_url(self, user):
        uid = encode_uid(user.pk)
        token = default_token_generator.make_token(user)
        url = f'{uid}/{token}'
        return url
    
    
class BaseUserService:
    model_class = User
    base_user_validation_service = BaseUserValidationService()
    token_service = TokenCreateService()
    
    def create(self, validated_data, **kwargs):
        groups = validated_data.pop("groups")
        validated_data["user_type"] = "admin"
        instance = self.model_class.objects.create(is_staff=True, **validated_data)
        for group in groups:
            instance.groups.add(group)
        password = self.model_class.objects.make_random_password(
            length=8, allowed_chars="abcdefghjkmnpqrstuvwxyz23456789"
        )
        instance.set_password(password)
        instance.save()
        return instance
    
    def update_status_from_activation(self, validated_data, **kwargs):
        user = self.base_user_validation_service.get_user_from_validated_uid(validated_data)
        self.base_user_validation_service.validate_activation_token(user, validated_data)
        
        user.is_active = True
        user.save()
        
        return user
    
    def update_password(self, user, validated_data, **kwargs):
        self.base_user_validation_service.validate_current_password(user, validated_data)
        self.base_user_validation_service.validate_password_with_retype_password(validated_data.get('new_password'), validated_data.get('re_type_new_password'))
        
        user.set_password(validated_data["new_password"])
        user.save()

        return user
    
    def get_user_by_email(self, email):
        try:
            return self.model_class.objects.get(email=email, is_active=True)
        except self.model_class.DoesNotExist:
            raise Http404
        
    
    def forget_password_url(self,validated_data, **kwargs):
        user = self.get_user_by_email(validated_data["email"])
        url = self.token_service.get_activation_token_url(user)
        return url
    
    def forget_password_activation(self, validated_data, **kwargs):
        user = self.base_user_validation_service.get_user_from_validated_uid(validated_data)
        self.base_user_validation_service.validate_activation_token(user, validated_data)
        self.base_user_validation_service.validate_password_with_retype_password(validated_data.get('password'), validated_data.get('re_type_password'))
        
        user.set_password(validated_data["password"])
        user.save()
        
        return user
    
    
class BasePassengerUserService:
    model_class = User
    base_user_validation_service = BaseUserValidationService()
    
    def create(self, validated_data, **kwargs):
        validated_data["user_type"] = "passenger"
        validated_data["is_active"] = False
        
        re_type_password = validated_data.pop("re_type_password")
        user = self.model_class(**validated_data)
        self.base_user_validation_service.validate_password(user, validated_data.get("password"))
        self.base_user_validation_service.validate_password_with_retype_password(validated_data.get("password"), re_type_password)
        
        instance = self.model_class.objects.create(is_staff=False, **validated_data)
        instance.groups.add(1)
        return instance 
        

