import uuid
import secrets
from functools import partial

import jwt
import random
import string
from datetime import datetime, timedelta

from django.core.validators import MinValueValidator, MaxValueValidator
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin, UserManager
)
from django.db import models
from phonenumber_field.modelfields import PhoneNumberField

from ultis.helper import custom_user_image_path


#Version



class User(AbstractBaseUser, PermissionsMixin):



    class CustomUserManager(BaseUserManager):
        def create_user(self, phone_number, **extra_fields):
            if not phone_number:
                raise ValueError('User must have a phone number.')

            user = self.model(phone_number=phone_number, **extra_fields)
            user.set_password(extra_fields.get('password', secrets.token_urlsafe(6)))
            user.save()
            return user

        def create_superuser(self, phone_number, **extra_fields):
            user = self.create_user(phone_number, **extra_fields, )
            user.is_superuser = True
            user.is_staff = True
            user.save()
            return user

    doc_image_path = partial(custom_user_image_path, path="docid")
    avatar_image_path = partial(custom_user_image_path, path="avatar")

    # Base
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_number = PhoneNumberField(unique=True, db_index=True)
    email = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    is_verify = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'phone_number'

    objects = CustomUserManager()

    # Kyc
    GENDER_CHOICES = (
        ('Male', 'Nam'),
        ('Female', 'Nữ'),
        ('Unknown', 'Không xác định'),
    )
    full_name = models.CharField(max_length=200, blank=True)
    gender = models.CharField(max_length=7, choices=GENDER_CHOICES, default='Unknown')
    date_of_birth = models.DateField(null=True)
    doc_id = models.CharField(max_length=20, blank=True)
    date_issued = models.DateField(null=True)
    date_expired = models.DateField(null=True)
    place_issued = models.CharField(max_length=200, blank=True)
    hometown = models.CharField(max_length=200, blank=True)
    permanent_address = models.CharField(max_length=200, blank=True)
    nationality = models.CharField(max_length=100, blank=True)
    avatar = models.ImageField(upload_to=avatar_image_path, default='user_media/images/avatar/default.png')
    front_id_image = models.ImageField(upload_to=doc_image_path, default='/')
    back_id_image = models.ImageField(upload_to=doc_image_path, default='/')

    # Rank
    ACCOUNT_TYPE_CHOICES = (
        ('base', 'Tài khoản tiêu chuẩn'),
        ('plus', 'Tài khoản Plus'),
        ('vip', 'Tài khoản VIP'),
        ('vvip', 'Tài khoản VVIP'),
    )
    account_type = models.CharField(max_length=50, choices=ACCOUNT_TYPE_CHOICES, default='base')

    # Payment
    points = models.PositiveIntegerField(default=0)

    # Notification
    device_token = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return self.full_name if len(self.full_name) > 0 else self.local_phone_number

    @property
    def local_phone_number(self):
        return str(self.phone_number).replace('+84', '0')

    @property
    def token(self):
        return self._generate_jwt_token()

    @property
    def new_password(self):
        new_pwd = secrets.token_urlsafe(6)
        self.set_password(new_pwd)
        self.save()
        return new_pwd

    def _generate_jwt_token(self):
        dt = datetime.now() + timedelta(days=60)

        token = jwt.encode({
            'id': str(self.pk),
            'exp': int(dt.timestamp())
        }, settings.SECRET_KEY, algorithm='HS256')

        return token







class OTP(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6, blank=True)
    log = models.TextField(blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now=True)

    @property
    def expires_at(self):
        return self.created_at + timedelta(minutes=15)

    @classmethod
    def generate_otp(cls):
        return ''.join(random.choices(string.digits, k=6))


class UserReview(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, related_name='user_reviews', on_delete=models.CASCADE)
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    feedback = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Review for {self.user} - Rating: {self.rating}"


@receiver(pre_save, sender=OTP)
def generate_otp(sender, instance, **kwargs):
    if not instance.code:
        instance.code = ''.join(random.choices(string.digits, k=6))