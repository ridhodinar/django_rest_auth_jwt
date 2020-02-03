from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import update_last_login
from django.shortcuts import render, redirect
from django.utils.encoding import force_bytes, force_text
from django.utils import timezone
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage
from django.http import HttpResponse

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenViewBase
from rest_framework_simplejwt.serializers  import TokenObtainPairSerializer

from .serializers import RegisterSerializer, ChangePasswordSerializer
from .token_generator import account_activation_token, reset_password_token
from .models import Account
from .permission import APILoginPermission

class LoginView(TokenViewBase):
    permission_classes = (APILoginPermission,)
    serializer_class = TokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        data = super().post(request, *args, **kwargs)

        account = Account.objects.get(username=request.data['username'])
        update_last_login(None, account)

        return data

@api_view(['POST'])
def register(req):
    serializer = RegisterSerializer(data=req.data)

    if serializer.is_valid():
        account = serializer.save()

        SendEmail(req, account)

        return Response({'detail':'successful create new user. Check email to activate the account'})
    else:
        return Response(serializer.errors)

@api_view(['GET','POST'])
def activate_account(req, **args):
    if req.method == 'GET' :
        return HttpResponse('click here !!!!!')
    
    if req.method == 'POST' :

        uidb64 = req.data['uid']
        token = req.data['token']

        try:
            uid = force_bytes(urlsafe_base64_decode(uidb64))
            account = Account.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
            account = None

        if account is not None and account_activation_token.check_token(account, token):
            
            account.is_active = True
            account.save()
            
            return Response({'detail':'Your account has been activate successfully'})
        else:
            return Response({'detail':'Activation link is invalid!'})

@api_view(['GET','POST'])
def reset_password(req, **args):
    if req.method == 'POST':
        
        account = Account.objects.get(email=req.data['email'])
        
        SendEmailPassword(req, account)
       
        return Response({'detail':'Please check your email to reset password'})
    
    if req.method == 'GET' :
        return HttpResponse('Resetting password . . .')

@api_view(['POST'])
def reset_password_confirm(req, **args):
    serializer = ChangePasswordSerializer(data=req.data)
    
    uidb64 = req.data['uid']
    token = req.data['token']

    if serializer.is_valid():
        
        try:
            uid = force_bytes(urlsafe_base64_decode(uidb64))
            account = Account.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
            account = None
        
        if account is not None and reset_password_token.check_token(account, token):
            
            account.set_password(serializer.validated_data)
            account.save()

            return Response({'detail':'Successfully reset password'})
        else:
            return Response({'detail':'Link is invalid!'})
    else:
        return Response(serializer.errors)

@api_view(['POST'])
@permission_classes((IsAuthenticated,))
def change_password(req):
    
    serializer = ChangePasswordSerializer(data=req.data)
    
    if serializer.is_valid():
    
            account = Account.objects.get(username=req.user.username)

            account.set_password(serializer.validated_data)
            account.save()

            return Response({'detail':'Successfully reset password'})
    else:
        return Response(serializer.errors)

def SendEmail(req, account):
    email_subject = 'Activate Your Account'
    message = render_to_string('account/activate_account_email.html', {
        'domain': req.get_host(),
        'uid': urlsafe_base64_encode(force_bytes(account.pk)),
        'token': account_activation_token.make_token(account),
    })
    to_email = account.email
    email = EmailMessage(email_subject, message, to=[to_email])
    email.send()

def SendEmailPassword(req, account):
    email_subject = 'Reset Password Instruction'
    message = render_to_string('account/reset_password_email.html', {
        'domain': req.get_host(),
        'uid': urlsafe_base64_encode(force_bytes(account.pk)),
        'token': reset_password_token.make_token(account),
    })
    to_email = req.data['email']
    email = EmailMessage(email_subject, message, to=[to_email])
    email.send()
