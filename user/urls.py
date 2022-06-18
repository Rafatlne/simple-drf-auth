from django.urls import path, include
from rest_framework.routers import DefaultRouter

from user.views import BaseUserViewSet,TokenCreateView, TokenDestroyView, BasePassengerUserViewSet, BaseUserActivation

router = DefaultRouter()
router.register("users", BaseUserViewSet)
router.register("passengers", BasePassengerUserViewSet)
router.register("activation", BaseUserActivation)


urlpatterns = [
    path('api/v1/', include(router.urls)),
    path("api/v1/users/token/login/", TokenCreateView.as_view(), name="login"),
    path("api/v1/users/token/logout/", TokenDestroyView.as_view(), name="logout"),
    
]