
from django.contrib import admin
from django.urls import path,include

urlpatterns = [

    path('api/v1/auth/',include('authentication.urls')),




    #Admin
    path('admin/', admin.site.urls),
]
