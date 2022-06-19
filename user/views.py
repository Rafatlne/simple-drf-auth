from django.contrib.auth import get_user_model
from rest_framework import generics, status, views, viewsets
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated


from .serializers import BaseUserSerializer, UserCreateTokenSerializer, TokenSerializer, BaseUserCreatePasswordRetypeSerializer, BaseUserActivationSerializer, BaseUserPasswordChangeSerializer, BaseUserPasswordForgotSerializer, BaseUserPasswordForgotActivationSerializer
from .services import BaseUserService, TokenCreateService, BasePassengerUserService

User = get_user_model()

class BaseUserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    service_class = BaseUserService()
    serializer_class = BaseUserSerializer
    
    def create(self, request, **kwargs):
        serializer = self.get_serializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)
        instance = self.service_class.create(serializer.data)
        return Response(self.serializer_class(instance).data, status=status.HTTP_201_CREATED)
    
    
class TokenCreateView(generics.CreateAPIView):
    """
    Use this endpoint to obtain user authentication token.
    """
    serializer_class = UserCreateTokenSerializer
    service_class = TokenCreateService()
        
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = self.service_class.create(serializer.data)

        return Response(
            data=TokenSerializer(token).data, status=status.HTTP_200_OK
        )


class TokenDestroyView(views.APIView):
    """
    Use this endpoint to logout user (remove user authentication token).
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        Token.objects.filter(user=request.user).delete()
        return Response({"details": "Token has been deleted"}, status=status.HTTP_200_OK)
    
    
    
class BasePassengerUserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    service_class = BasePassengerUserService()
    serializer_class = BaseUserCreatePasswordRetypeSerializer
    
    def create(self, request, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = self.service_class.create(serializer.data)
        token_service = TokenCreateService()
        url = token_service.get_activation_token_url(instance)
        # return Response(BaseUserSerializer(instance).data, status=status.HTTP_201_CREATED)
        
        return Response({"url" : url}, status=status.HTTP_201_CREATED)
    
    
class BaseUserActivation(viewsets.ModelViewSet):
    queryset = User.objects.all()
    service_class = BaseUserService()
    serializer_class = BaseUserActivationSerializer
    
    def create(self, request, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.service_class.update_status_from_activation(serializer.data)
        return Response({"detail" : "user has been activated"}, status=status.HTTP_200_OK)
    
    
class BaseUserPasswordChangeViewset(viewsets.ModelViewSet):
    queryset = User.objects.all()
    service_class = BaseUserService()
    serializer_class = BaseUserPasswordChangeSerializer
    permission_classes = [IsAuthenticated]
    
    def create(self, request, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.service_class.update_password(request.user, serializer.data)
        return Response({"detail" : "password has been updated"}, status=status.HTTP_200_OK)
    
class BaseUserPasswordForgotViewset(viewsets.ModelViewSet):
    queryset = User.objects.all()
    service_class = BaseUserService()
    serializer_class = BaseUserPasswordForgotSerializer
    
    def create(self, request, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        forget_password_url = self.service_class.forget_password_url(serializer.data)
        return Response({"url" : forget_password_url}, status=status.HTTP_200_OK)

class BaseUserPasswordForgotActivationViewset(viewsets.ModelViewSet):
    queryset = User.objects.all()
    service_class = BaseUserService()
    serializer_class = BaseUserPasswordForgotActivationSerializer
    
    def create(self, request, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.service_class.forget_password_activation(serializer.data)
        return Response({"detail" : "user password has been updated"}, status=status.HTTP_200_OK)