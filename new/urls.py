from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ArticleViewSet, UserCreateView, CustomAuthToken, UpdateUserRoleView

router = DefaultRouter()
router.register(r'articles', ArticleViewSet)

urlpatterns = [
    path('register/', UserCreateView.as_view(), name='user-register'),
    path('login/', CustomAuthToken.as_view(), name='api_token_auth'),
    path('update-user-role/<int:pk>/', UpdateUserRoleView.as_view(), name='update-user-role'),
    path('', include(router.urls)),
]