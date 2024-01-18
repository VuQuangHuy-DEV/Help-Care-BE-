from django.urls import path

from authentication.views import LoginAPIView, RegisterAPIView, VerifyUserView, GetUserInfoAPIView, \
    DeleteUserInfoAPIView, UpdateUserInfoAPIView

urlpatterns = [
    path("login/", LoginAPIView.as_view()),
    path("register/", RegisterAPIView.as_view()),
    path('user/verify/', VerifyUserView.as_view()),
    path('user/info/', GetUserInfoAPIView.as_view()),
    path('user/update/', UpdateUserInfoAPIView.as_view()),
    path('user/delete/', DeleteUserInfoAPIView.as_view()),


]