from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render, redirect
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage
from django.http import HttpResponse

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import RegisterSerializer
from .token_generator import account_activation_token
from .models import Account
from .permission import APILoginPermission

@api_view(['GET'])
@permission_classes((IsAuthenticated,))
def test(req):
    return Response({
        'id':req.user.id,
        'username':req.user.username,
    })

class LoginView(TokenObtainPairView):
    permission_classes = (APILoginPermission,)

@api_view(['POST'])
def register(req):
    serializer = RegisterSerializer(data=req.data)
    if serializer.is_valid():
        account = serializer.save()

        SendEmail(req, account)

        return Response({'message':'successful create new user. Check email to activate the account'})
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
            return Response({'message':'Your account has been activate successfully'})
        else:
            return Response({'message':'Activation link is invalid!'})


def SendEmail(req, account):
    #current_site = Site.objects.get_current()
    email_subject = 'Activate Your Account'
    message = render_to_string('account/activate_account_email.html', {
        'user': account,
        'domain': req.get_host(),
        'uid': urlsafe_base64_encode(force_bytes(account.pk)),
        'token': account_activation_token.make_token(account),
    })
    to_email = account.email
    email = EmailMessage(email_subject, message, to=[to_email])
    email.send()
