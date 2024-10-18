from django.urls import path
from . import views
from django.contrib.auth import views as auth_views



urlpatterns = [
    path('', views.Home.as_view()),    
    # path('login/', auth_views.LoginView.as_view(template_name='products/login.html'), name='login'),
    # path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('register/', views.RegisterAPIView.as_view(), name='register'),
    path('myuser/', views.GetUser.as_view(), name='getuser'),
    path('login/', views.LoginAPIView.as_view(), name='login'),
    path('update-password/', views.UpdateUser.as_view(), name='updatepassword'),
    path('delete-user/', views.DeleteUser.as_view(), name='delete_user'),
    path('logout/', views.LogOut.as_view(), name='logout'),
    path('api/products/', views.ProductListAPIView.as_view(), name='product_list'),
    path('api/products/create/', views.ProductCreateAPIView.as_view(), name='product_create'),
    path('api/products/<int:pk>/', views.ProductDetailAPIView.as_view(), name='product_detail'),
    path('api/products/<int:pk>/update/', views.ProductUpdateAPIView.as_view(), name='product_update'),
    path('api/products/<int:pk>/delete/', views.ProductDeleteAPIView.as_view(), name='product_delete'),
    path('api/products/search/', views.ProductSearchAPIView.as_view(), name='product_search')
]