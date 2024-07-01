from django.conf import settings
from django.utils import timezone
from django.middleware import csrf
from django.http import QueryDict

from rest_framework import generics, status, exceptions
from rest_framework.views import APIView
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

from .serializers import CustomUserSerializer, LoginSerializer

#===================Authentication APIs===================

class Register(generics.GenericAPIView):
    permission_classes = []
    serializer_class = CustomUserSerializer

    def post(self, request):
        """
        Create a new user account.

        Parameters:
        - request: The HTTP request object.

        Returns:
        - Response: The HTTP response object with a success message and status code 200 if the account is registered successfully.

        Raises:
        - ValidationError: If the serializer data is invalid.

        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({"message": "Account is registered"}, status=status.HTTP_201_CREATED)

class Login(generics.GenericAPIView):
    permission_classes = []
    serializer_class = LoginSerializer

    def post(self, request):
        """
        Handle POST request for user login.

        Parameters:
        - request: The HTTP request object.

        Returns:
        - response: The HTTP response object containing the access and refresh tokens.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        
        # Generate the refresh and access tokens
        refresh = RefreshToken.for_user(user)
        data = {
            "refreshToken": str(refresh),
            "accessToken": str(refresh.access_token)
        }
        
        # Set the access and refresh tokens for the Http cookie
        response = Response()
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=data["accessToken"],
            expires=timezone.now() + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
            value=data["refreshToken"],
            expires=timezone.now() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )

        response["X-CSRFToken"] = csrf.get_token(request)

        data = {'message': 'Login successfully'}
        response.data = data

        return response
        
class Logout(APIView):

    def post(self, request):
        """
        Handles the POST request for user logout.

        Args:
            request: The HTTP request object.

        Returns:
            A Response object with a success message.

        Raises:
            exceptions.ParseError: If the token is invalid.
        """
        try:
            # Get the refresh token from the request cookies
            refreshToken = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'], None)

            # Blacklist the refresh token
            token = RefreshToken(refreshToken)
            token.blacklist()

            response = Response()
            # Delete the access and refresh token cookies
            response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
            response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            # Delete the CSRF token cookies and CSRF token header
            response.delete_cookie("csrftoken")
            response["X-CSRFToken"]=None

            data = {'message': 'Logout successfully'}
            response.data = data
            
            return response
        except:
            raise exceptions.ParseError("Invalid token")
        
class RefreshAcessToken(TokenRefreshView):
    permission_classes = []

    def post(self, request, *args, **kwargs):
        """
        Handles the POST request to refresh an access token.

        Args:
            request (HttpRequest): The HTTP request object.
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            HttpResponse: The HTTP response object with new access and refresh tokens (old refresh token is blacklisted).

        Raises:
            exceptions.ParseError: If the refresh token is missing in the request cookies.

        """
        # Get the refresh token from the request cookies
        refreshToken = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'], None)

        if refreshToken is not None:
            # Check if the request data is immutable to set it mutable to add the refresh token
            if isinstance(request.data, QueryDict):
                request.data._mutable = True
            request.data['refresh'] = refreshToken
            request.data._mutable = False
        else:
            raise exceptions.ParseError("Refresh token is missing")

        # Call the parent class's post method to refresh the tokens
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            # Set the new access and refresh tokens in the response cookies
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                value=response.data['access'],
                expires=timezone.now() + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=response.data['refresh'],
                expires=timezone.now() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )
            response["X-CSRFToken"] = request.COOKIES.get("csrftoken")

            data = {'message': 'Refresh tokens successfully'}
            response.data = data

        return response

class AuthStatus(APIView):

    def post(self, request):
        """
        Parameters:
            request: a POST request to check authentication status.

        Returns:
            a Response object with data {"status": "Authenticated"}.
            
        Raises:
            exceptions.ParseError: If the refresh token is blacklisted.

        """
        # Check if the refresh token exists in the request cookies
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'], None)

        # Create a RefreshToken object using the refresh token
        token = RefreshToken(refresh_token)

        # Check if the token is blacklisted
        if BlacklistedToken.objects.filter(token__jti=token['jti']).exists():
            raise exceptions.ParseError("Token is blacklisted")

        return Response({"status": "Authenticated"}, status=status.HTTP_200_OK)

