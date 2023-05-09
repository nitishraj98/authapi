
from django.urls import path
from account.views import userRegistrationView
from account.views import userLoginView
from account.views import userProfileView
from account.views import UpdatePasswordView,SendPasswordResetEmailView,UserPasswordResetView
from. import views
urlpatterns = [
    path('register/', userRegistrationView.as_view(),name='register'),
    path('login/', userLoginView.as_view(),name='login'),
    path('profile/', userProfileView.as_view(),name='profile'),
    path('updatePassword/', UpdatePasswordView.as_view(),name='updatePassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(),name='sendResetPaswword'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(),name='ResetPaswword'),
    path('user/', views.user_dashboard, name='user_dashboard'),
   

]
 