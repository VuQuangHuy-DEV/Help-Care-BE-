from django.shortcuts import render

# Create your views here.
from django.contrib.auth import authenticate, login
from django.contrib.auth.password_validation import validate_password
from phonenumbers import parse
from django.views import generic
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.models import User, OTP
from authentication.serializers import LoginSerializer, VerifyUserSerializer, CreateAdminUserSerializer, \
    AdminUserLoginSerializer, UpdateAdminPasswordSerializer, ResetAdminPasswordSerializer, GetUserInfoSerializer, \
    UpdateUserInfoSerializer
from core import settings
from ultis.helper import validate_email_address, get_validate_date, get_full_image_url, convert_phone_number, \
    send_email, send_log_email
from ultis.api_helper import api_decorator


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)

    @api_decorator
    def post(self, request):
        phone_number = request.data.get('phone_number', None)
        password = request.data.get('password', None)

        if not (phone_number and password):
            return {}, "Missing required fields", status.HTTP_400_BAD_REQUEST

        send_log_email(request)
        phone_number = convert_phone_number(phone_number)

        user = authenticate(phone_number=phone_number, password=password)

        if user is None:
            return {}, "Invalid phone number or password", status.HTTP_401_UNAUTHORIZED

        response_data = {
            'phone_number': user.local_phone_number,
            'id': str(user.id),
            'is_active': user.is_active,
            'is_verify': user.is_verify,
            'is_staff': user.is_staff,
            'created_at': user.created_at,
            'token': user.token

        }

        return response_data, "Login successful", status.HTTP_200_OK


class RegisterAPIView(APIView):
    permission_classes = (AllowAny,)

    @api_decorator
    def post(self, request):
        phone_number = request.data.get('phone_number', None)
        password1 = request.data.get('password1', None)
        password2 = request.data.get('password2', None)

        if not (phone_number and password1 and password2):
            return {}, "Missing required fields", status.HTTP_400_BAD_REQUEST

        send_log_email(request)
        phone_number = convert_phone_number(phone_number)

        if User.objects.filter(phone_number=phone_number).exists():
            return {}, "User already exists", status.HTTP_400_BAD_REQUEST

        if password1 != password2:
            return {}, "Passwords do not match", status.HTTP_400_BAD_REQUEST

        user = User.objects.create_user(phone_number=phone_number)
        user.set_password(password1)
        user.points = 1000
        user.save()

        response_data = {
            'phone_number': user.local_phone_number,
            'id': str(user.id),
            'is_active': user.is_active,
            'is_verify': user.is_verify,
            'is_staff': user.is_staff,
            'created_at': user.created_at,
            'token': user.token

        }

        return response_data, "Register successful", status.HTTP_201_CREATED


class VerifyUserView(APIView):
    permission_classes = (IsAuthenticated,)

    @api_decorator
    def post(self, request):
        phone_number = request.user.phone_number

        if not User.objects.filter(phone_number=phone_number).exists():
            raise ValueError("User doest not exist")

        user = User.objects.get(phone_number=phone_number)
        user.is_verify = True
        user.save()
        serializer = VerifyUserSerializer(user, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            serializer.is_verify = True
            serializer.save()
            data = serializer.data

            return data, "Verify user successfully", status.HTTP_200_OK
        return Response({
            "status_code": status.HTTP_400_BAD_REQUEST,
            "message": "Invalid data format",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class GetUserInfoAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    @api_decorator
    def get(self, request):
        phone_number = request.user.phone_number
        user = User.objects.get(phone_number=phone_number)
        serializer = GetUserInfoSerializer(user, context={'request': request})
        return serializer.data, "Retrieve data successfully", status.HTTP_200_OK


class UpdateUserInfoAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    @api_decorator
    def put(self, request):
        phone_number = request.user.phone_number

        if not User.objects.filter(phone_number=phone_number).exists():
            raise ValueError("User doest not exist")

        user = User.objects.get(phone_number=phone_number)
        serializer = UpdateUserInfoSerializer(user, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return serializer.data, "Update user successfully", status.HTTP_200_OK


class DeleteUserInfoAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    @api_decorator
    def delete(self, request):
        phone_number = request.user.phone_number
        user = User.objects.get(phone_number=phone_number)
        user.delete()
        return {}, "Delete user successfully", status.HTTP_204_NO_CONTENT


