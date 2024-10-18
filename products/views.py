from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import AllowAny
from .models import *
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from .models import Product
from .serializers import ProductSerializer
from django.shortcuts import get_object_or_404
from rest_framework.pagination import PageNumberPagination

class Home(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        content = {'message': 'Hello, World!'}
        return Response(content)

class RegisterAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            validate_password(password)
            user = Users.objects.create_user(username, email, password)
            user.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        logged_user = authenticate(username=username, password=password)
        if logged_user is not None:
            refresh = RefreshToken.for_user(logged_user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)


class GetUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        content = {'message': f"current username is {request.user.username}"}
        return Response(content)
    
class UpdateUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        new_password = request.data.get('new_password')
        repeat_new_password = request.data.get('repeat_new_password')
        logged_user = authenticate(username=username, password=password)
        if logged_user is not None:
            if request.user.username != username:
                content = {'message': "You are only allowed to change your credentials!"}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)
            if new_password != repeat_new_password:
                content = {'message': "Passwords don't match!"}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)
            try:
                validate_password(new_password)
            except ValidationError as e:
                return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)
            logged_user.set_password(new_password)
            logged_user.save()
            content = {'message': "Password changed successfully!"}
            return Response(content,  status=status.HTTP_202_ACCEPTED)
        else:
            content = {'message': "User Credentials are not correct!"}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)


class DeleteUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        refresh_token = request.data.get("refresh")
        logged_user = authenticate(username=username, password=password)
        if logged_user is not None:
            if request.user.username != username:
                content = {'message': "You are only allowed to delete your account!"}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()
            logged_user.delete()
            content = {'message': "We are sad to let you go :( !!"}
            return Response(content,  status=status.HTTP_202_ACCEPTED)
        else:
            content = {'message': "User Credentials are not correct!"}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)
        

class LogOut(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        Refresh_token = request.data["refresh"]
        token = RefreshToken(Refresh_token)

        token.blacklist()
        content = {'message': "Logged out successfully!"}
        return Response(content,  status=status.HTTP_205_RESET_CONTENT)
    

class ProductListAPIView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        products = Product.objects.all()
        category = request.query_params.get('category', None)
        min_price = request.query_params.get('min_price', None)
        max_price = request.query_params.get('max_price', None)
        in_stock = request.query_params.get('in_stock', None)
        if category:
            products = products.filter(category__iexact=category)  # Exact match for category

        # Filter by price range if provided
        if min_price is not None:
            products = products.filter(price__gte=min_price)
        if max_price is not None:
            products = products.filter(price__lte=max_price)

        # Filter by stock availability if specified
        if in_stock is not None:
            if in_stock.lower() == 'true':
                products = products.filter(stock_quantity__gt=0)  # In stock
            elif in_stock.lower() == 'false':
                products = products.filter(stock_quantity=0)  # Out of stock

        # Paginate results
        paginator = PageNumberPagination()
        paginated_products = paginator.paginate_queryset(products, request)

        serializer = ProductSerializer(paginated_products, many=True)
        return paginator.get_paginated_response(serializer.data)

class ProductCreateAPIView(APIView):
    def post(self, request):
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProductUpdateAPIView(APIView):
    def put(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        serializer = ProductSerializer(product, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductDeleteAPIView(APIView):
    def delete(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        product.delete()
        return Response({"message": "Product deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

class ProductDetailAPIView(APIView):
    permission_classes = [AllowAny]
    def get(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        serializer = ProductSerializer(product)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class ProductSearchAPIView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        # Get search parameters from the query string
        name = request.query_params.get('name', None)
        category = request.query_params.get('category', None)

        # Filter products based on search parameters
        products = Product.objects.all()

        if name:
            products = products.filter(name__icontains=name)  # Partial match for name
        if category:
            products = products.filter(category__iexact=category)  # Exact match for category

        # Paginate results
        paginator = PageNumberPagination()
        paginated_products = paginator.paginate_queryset(products, request)

        serializer = ProductSerializer(paginated_products, many=True)
        return paginator.get_paginated_response(serializer.data)