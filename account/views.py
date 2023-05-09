from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UpdatePasswordSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required
def user_dashboard(request):
    return render(request, "user_dashboard.html")



def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),    
        'access': str(refresh.access_token),
    }

  
class userRegistrationView(APIView): 
    def post (self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
          user = serializer.save()
          token = get_tokens_for_user(user)
          return Response({'token':token,'msg':'Registration success'})
          status=status.HTTP_201_CREATED
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

from django.shortcuts import redirect

class userLoginView(APIView):
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                if user.is_staff:
                    # Redirect staff to user dashboard
                    return redirect('user_dashboard.html')
                return Response({'token': token, 'msg': 'Login success'}, status=status.HTTP_200_OK)
            else:
                error_msg = 'Invalid email or password'
                return Response({'errors': {'non_field_errors': [error_msg]}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class userProfileView(APIView):
   permission_classes = [IsAuthenticated]
   def get (self, request, format=None):
      serializer = UserProfileSerializer(request.user)
     
      return Response(serializer.data,status=status.HTTP_200_OK) 
   
 
class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):    
        serializer = UpdatePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():    
            serializer.save()
            return Response({'msg': 'Password updated successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)   
     
class SendPasswordResetEmailView(APIView): 
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
             return Response({'msg':'Password Reset link Send, Please check your Email'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 
 
class UserPasswordResetView(APIView): 
    def post(self,request,uid,token,format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context = {'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset Succesfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  