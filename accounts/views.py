from django.shortcuts import render
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from .serializers import UserSerializer
from rest_framework.decorators import api_view,permission_classes
from rest_framework import status 
from rest_framework.response import Response
from rest_framework.permissions  import IsAuthenticated,AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes

User = get_user_model()

@api_view(['POST'])
def register_user(request):
    
    try:
        email = request.data.get("email")
        password = request.data.get("password")
        username = request.data.get("username")
        
        if User.objects.filter(email=email).exists() :
            return Response({'email': 'Email already exists'},status=status.HTTP_400_BAD_REQUEST)
        
        if len(password) < 6:
            return Response({'password': 'Password must be at least 6 characters'},status=status.HTTP_400_BAD_REQUEST)
        
        if len(password) < 8:
            return Response({'password': 'Password must be at least 6 characters'},status=status.HTTP_400_BAD_REQUEST)

        if password.lower() in ["password", "123456", "abcdef", "abc123"]:
            return Response({'password': 'Password is too common'},status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.create_user(username=username,email=email,password=password)
        user.save()
        return Response({"message": "User registered successfully!"}, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({"message": str(e)},status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(username=email,password=password)
    if user is not None:
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        
        return Response(
            {"message": "Login successful", 
             "email": user.email,
             "refresh": str(refresh),
             "access": str(access),
             },
            status=status.HTTP_200_OK  # ✅ integer constant
        )
    else:
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_401_UNAUTHORIZED  # ✅ integer constant
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])

def user_profile(request):
    user = request.user
    profile_data = {
        "id":user.id,
        "email":user.email,
        "username":user.username,
    }
    return Response(profile_data,status=status.HTTP_200_OK)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])

def update_profile(request):
    user = request.user
    username = request.data.get('username')
    email = request.data.get('email')

    if username:
        user.username = username
    if email:
        user.email = email
    user.save()
    return Response({'message': 'Profile updated successfully',
                     "username": user.username,
                     "email": user.email},
                     status=status.HTTP_200_OK)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])

def delete_profile(request):
    try:
        user = request.user
        user.delete()
        return Response({"message":"User delete successfully"},status=status.HTTP_200_OK)
    except Exception as e :
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# from django.conf import settings

# @api_view(['POST'])
# @permission_classes([AllowAny])  # ✅ anyone (login or not) can use
# def forgot_password_request(request):
#     """
#     Send password reset link.
#     Case 1: logged-in → use request.user.email
#     Case 2: not logged-in → user enters email manually
#     """
#     email = request.data.get("email")

#     # Case 1: logged-in user (if token valid)
#     if request.user.is_authenticated:
#         user = request.user
#     else:
#         # Case 2: not logged in → use email from input
#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)

#     token = default_token_generator.make_token(user)
#     uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
#     reset_url = f"http://localhost:5173/reset-password/{uidb64}/{token}/"

#     send_mail(
#         subject="Password Reset Link",
#         message=f"Hi {user.username},\n\nClick this link to reset your password:\n{reset_url}",
#         from_email=settings.EMAIL_HOST_USER,
#         recipient_list=[user.email],
#         fail_silently=False,
#     )

#     return Response({"message": f"Reset link sent to {user.email}"}, status=status.HTTP_200_OK)


# @api_view(['POST'])

# def forgot_password(request):
#     email = request.data.get("email")

#     try:
#         user = User.objects.get(email=email)
#     except User.DoesNotExist:
#         return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)
    
#     token = default_token_generator.make_token(user)
#     uidb64  = urlsafe_base64_encode(force_bytes(user.pk))

#     reset_link = f"http://127.0.0.1:8000/reset-password/{uidb64}/{token}/"
        
#     subject = "Password Reset Request"
#     message = f"Hi {user.username},\n\nClick the link below to reset your password:\n{reset_link}\n\nIf you didn’t request this, please ignore it."
#     from_email = 'himanshuvaghasiya01@gmail.com'
#     recipient_list = [user.email]

#     send_mail(subject,message,from_email,recipient_list,fail_silently=False)

#     return Response({'message': 'Password reset email sent',
#                      "reset-link": reset_link})
    
    

# @api_view(['POST'])

# def reset_password(request,uidb64,token):
#     try:
#         uid = urlsafe_base64_decode(uidb64).decode()
#         user = User.objects.get(pk=uid)
#     except (TypeError,ValueError,OverflowError,User.DoesNotExist):
#         return Response({"error": "Invalid UID"},status=status.HTTP_400_BAD_REQUEST)
    
#     if not default_token_generator.check_token(user,token):
#         return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
    
#     new_password = request.data.get('password')
#     if not new_password:
#         return Response({"error": "password is required"}, status=status.HTTP_400_BAD_REQUEST)

#     user.set_password(new_password)
#     user.save()

#     return Response({"message": "Password reset successfully ✅"}, status=status.HTTP_200_OK)

from django.contrib.auth import update_session_auth_hash

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    current_password = request.data.get('current_password')
    new_password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')

    # Check old password
    if not user.check_password(current_password):
        return Response({'error': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)

    # Match new and confirm
    if new_password != confirm_password:
        return Response({'error': 'New passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

    # Update password
    user.set_password(new_password)
    user.save()

    # Keep user logged in after changing password
    update_session_auth_hash(request, user)

    return Response({'message': 'Password changed successfully!'}, status=status.HTTP_200_OK)

@api_view(['POST'])
def forgot_password(request):
    email = request.data.get("email")
    new_password = request.data.get("new_password")

    try:
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()
        return Response({"message": "Password reset successfully!"}, status=200)
    except User.DoesNotExist:
        return Response({"error": "No user found with this email"}, status=404)    

from django.core.mail import send_mail
from django.http import JsonResponse

def send_test_email(request):
    send_mail(
        subject="Hello Himanshu 👋",  # Email ka title
        message="Ye Django se bheja gaya test email hai.",  # Email ka body
        from_email="himanshuvaghasiya01@gmail.com",  # Jo settings me likha tha
        recipient_list=["hhit4237@gmail.com"],  # Jisko mail bhejna hai
        fail_silently=False,  # Agar koi error aaye to show kare
    )
    return JsonResponse({"message": "Email sent successfully!"})

