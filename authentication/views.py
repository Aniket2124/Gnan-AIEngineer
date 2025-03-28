from django.contrib.auth import authenticate, login, logout
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from drf_yasg.utils import swagger_auto_schema

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import SessionAuthentication

from .serializers import UserSerializer, VerifyAccountSerializer
from .emails import send_otp_via_mail
from .models import User



# Create your views here.
@method_decorator(csrf_exempt, name='dispatch')
class User_Registration_API(APIView):
    authentication_classes = [] 
    permission_classes = [AllowAny]
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            send_otp_via_mail(serializer.data['email'])
            return Response({'message':'Registration successful, Please check Your email for OTP To verify your Account'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class Verify_OTP(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(request_body=VerifyAccountSerializer)
    def post(self, request):
        serializer = VerifyAccountSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.data['email']
            otp = serializer.data['otp']
            user = User.objects.filter(email = email)
            if not user.exists():
                return Response({
                    'status':400,
                    'message':'Something Went Wrong', 
                    'data':'Invalid Email'
                    })
            if user[0].otp != otp:
                return Response({
                    'status':400,
                    'message':'Something Went Wrong', 
                    'data':'Invalid Email'
                    })
            user = user.first()
            user.is_verified = True
            user.is_active = True
            user.is_staff = True
            user.save()
            return Response({
                'status': 200,
                'message': 'Account successfully verified',
                'data': {}
            }, status=status.HTTP_200_OK)
        return Response({
            'status': 400,
            'message': 'Invalid Email',
            'data': 'No user found with the provided email.'
        }, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request=request, email=email, password=password)
        if user and user.is_active:
            login(request, user)
            response = Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
            response.set_cookie('auth_token', user.get_session_auth_hash(), httponly=True, secure=True)
            response.set_cookie('csrftoken', get_token(request), httponly=False)

            return response
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
    
@method_decorator(csrf_exempt, name='dispatch')
class LogoutView(APIView):
    authentication_classes = [] 
    permission_classes = [AllowAny]
    def post(self, request):
        logout(request)
        response = Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
        response.delete_cookie('auth_token')
        response.delete_cookie('csrftoken') 
        return response
    


class UserDetailsView(APIView):
    authentication_classes = [SessionAuthentication]  # Uses default authentication from settings
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user       
        return Response({
            'id': user.id,
            'email': user.email,
            'created_at': user.created_at,
        })
    