from django.urls import path

from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    register, 
    activate_account, 
    test, 
    LoginView
)


urlpatterns = [
    path('register/', register),
    path('activate/', activate_account),
    path('login/', LoginView.as_view()),
    path('token-refresh/', TokenRefreshView.as_view()),
    path('reset-password/', test),
    path('reset-password/confirm/', test),
    path('change-password/', test),

    path('test/', test),
]