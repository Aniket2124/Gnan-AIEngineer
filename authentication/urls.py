from django.urls import path
from authentication import views

urlpatterns = [
    path('register/', views.User_Registration_API.as_view(), name='register'),
    path('register/verify/', views.Verify_OTP.as_view(), name='verify'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('me/', views.UserDetailsView.as_view(), name='details'),
]