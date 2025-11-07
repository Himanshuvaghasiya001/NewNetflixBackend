from django.contrib import admin
from django.urls import path
from accounts import views as account_views  # 👈 alias use karo
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', account_views.register_user, name='register'),
    path('login/', account_views.login_user, name='login'),
    path('profile/', account_views.user_profile, name='profile'),
    path('update-profile/', account_views.update_profile, name='update_profile'),
    path('delete-profile/', account_views.delete_profile, name='delte_profile'),
    path('forgot-password/', account_views.forgot_password, name='forgot_password'),
    # path('forgot-password/', account_views.forgot_password_request, name='forgot_password'),
    # path('reset-password/<uidb64>/<token>/', account_views.reset_password, name='reset_password'),
    path('change-password/', account_views.change_password, name='change_password'),
    path('send-test-email/', account_views.send_test_email, name='send_test_email'),
    # path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

]
