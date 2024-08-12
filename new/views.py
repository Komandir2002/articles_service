from rest_framework import viewsets, generics, permissions
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Article, User
from .serializers import ArticleSerializer, UserSerializer, AuthTokenSerializer
from rest_framework.exceptions import PermissionDenied
from django.contrib.auth import authenticate
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response

class ArticleViewSet(viewsets.ModelViewSet):
    queryset = Article.objects.all()
    serializer_class = ArticleSerializer

    def get_queryset(self):
        if self.request.user.is_authenticated and self.request.user.is_subscriber:
            # Подписчики видят все статьи
            return Article.objects.all()
        # Неавторизованные пользователи видят только публичные статьи
        return Article.objects.filter(is_public=True)

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAuthenticated()]
        return [AllowAny()]

    def perform_create(self, serializer):
        if self.request.user.is_authenticated and self.request.user.is_author:
            serializer.save(author=self.request.user)  # Автоматически устанавливаем автора
        else:
            raise PermissionDenied("Only authors can create articles.")

    def perform_update(self, serializer):
        article = self.get_object()
        if self.request.user == article.author:
            serializer.save()
        else:
            raise PermissionDenied("You can only edit your own articles.")

    def perform_destroy(self, instance):
        if self.request.user == instance.author:
            instance.delete()
        else:
            raise PermissionDenied("You can only delete your own articles.")

class UserCreateView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        serializer.save(is_subscriber=True)  # Установим подписчика по умолчанию

class CustomAuthToken(ObtainAuthToken):
    serializer_class = AuthTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = authenticate(email=email, password=password)

        if user is None:
            return Response({"error": "Invalid credentials"}, status=400)

        try:
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'email': user.email,
                'username': user.username
            })
        except Exception as e:
            return Response({"error": str(e)}, status=500)

class UpdateUserRoleView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        user = self.get_object()
        if not request.user.is_superuser:
            return Response({"detail": "You do not have permission to update this user's role."}, status=403)

        data = request.data
        if 'is_author' in data:
            user.is_author = data['is_author']
            user.save()
            return Response({"detail": "User role updated successfully."}, status=200)
        return Response({"detail": "Invalid data."}, status=400)
