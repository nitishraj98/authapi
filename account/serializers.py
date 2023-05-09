from rest_framework import serializers
from account.models import User
from rest_framework.exceptions import ValidationError
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from account.utils import util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model = User
        fields =['email', 'name','password','password2','tc']
        extra_kwargs = {'password':{'write_only':True}, 'is_admin': {'write_only': True}}
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("password and confirm password doesn't match")
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        validated_data.pop('password2')
        user = User.objects.create_user(password=password, **validated_data)
        return user

      
class UserLoginSerializer(serializers.ModelSerializer):
   email = serializers.EmailField(max_length=255)
   class Meta:  
      model=User
      fields = ['email','password']

class UserProfileSerializer(serializers.ModelSerializer):
   class Meta:  
      model=User
      fields = ['id','email','name']


class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password2 = serializers.CharField(required=True, style={'input_type': 'password'})
    

    def validate(self, attrs):
        user = self.context['request'].user
        if not user.check_password(attrs['old_password']):
            raise ValidationError('Incorrect old password')
        if attrs['new_password'] != attrs['new_password2']:
            raise ValidationError("New passwords don't match")
        return attrs

    def save(self):  
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user    


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']


    def validate(self,attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():       
            user=User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded Uid', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset Token',token)
            link = 'http://localhost:8000/api/user/reset/'+uid+'/'+token
            print('Password Reset link',link)

            #email
            body = 'Click Following Link to Reset Your Password  ' + link
            data = {
                'subject':'Reset Your Password',
                'body':body,
                'to_email':user.email                                                                                  
            } 
            util.send_email(data)
          
            return attrs
        else:
            raise ValidationError('you are not a registered user')
    

class UserPasswordResetSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password2 = serializers.CharField(required=True, style={'input_type': 'password'})

def validate(self, attrs):
    try:
        user = self.context.get('request').user
        uid = self.context.get('uid')
        token = self.context.get('token')

        if not user.check_password(attrs['old_password']):
            raise ValidationError('Incorrect old password')
        if attrs['new_password'] != attrs['new_password2']: 
            raise ValidationError("New passwords don't match")
        id = smart_str(urlsafe_base64_decode(uid))
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user,token):
            raise ValidationError('Token is not valid or Expired')
            
        return attrs
            
    except DjangoUnicodeDecodeError as identifier:
        PasswordResetTokenGenerator().check_token(user,token)
        raise ValidationError('Token is not valid or Expired')

    

    
   
          
    
          