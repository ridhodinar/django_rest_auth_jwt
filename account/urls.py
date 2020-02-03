from django.urls import path

from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    register, 
    activate_account, 
    test, 
    LoginView,
    reset_password,
    reset_password_confirm
)


urlpatterns = [
    path('register/', register),
    path('activate/', activate_account),
    path('login/', LoginView.as_view()),
    path('token-refresh/', TokenRefreshView.as_view()),
    path('reset-password/', reset_password),
    path('reset-password/confirm/', reset_password_confirm),
    #path('change-password/', test),

    path('test/', test),
]