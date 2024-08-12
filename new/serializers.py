from rest_framework import serializers
from .models import User, Article
from django.core.validators import RegexValidator

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[
        RegexValidator(
            regex=r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$',
            message="Password must be at least 8 characters long and contain at least one letter and one number."
        )
    ])

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'is_author', 'is_subscriber']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User(
            email=validated_data['email'],
            username=validated_data['username'],
            is_author=validated_data.get('is_author', False),
            is_subscriber=validated_data.get('is_subscriber', False),
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
class ArticleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Article
        fields = ['title', 'content', 'is_public']
class AuthTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()