from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from rest_framework import authentication, exceptions

def check_csrf(request):
    # Get the CSRF token from the request's cookies
    csrf_token = request.COOKIES.get('csrftoken')

    # Check if the CSRF token is missing
    if csrf_token is None:
        raise exceptions.PermissionDenied('CSRF Failed: CSRF token missing')

    # Set the CSRF token in the request's headers
    request.META['HTTP_X_CSRFTOKEN'] = csrf_token

    # Perform CSRF check
    check = authentication.CSRFCheck(request)
    reason = check.process_view(request, None, (), {})

    # If CSRF check fails, raise an exception
    if reason:
        raise exceptions.PermissionDenied(f'CSRF check failed: {reason}')

class CustomAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Get the token from the cookie
        raw_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'], None)

        if raw_token is None:
            return None

        # Validate the token
        validated_token = self.get_validated_token(raw_token)

        # Enforce CSRF check
        check_csrf(request)

        # Return the user and validated token
        return self.get_user(validated_token), validated_token
    