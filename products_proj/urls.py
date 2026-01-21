from django.urls import path
from products_proj.apps import ProductsProjConfig
from .views import ProductListView, ProductDetailView, ContactsView

app_name = ProductsProjConfig.name

# urlpatterns = [
#     path('', views.index, name='home'),
#     path('products/<int:pk>/', views.product_detail, name='product_detail'),
# ]

urlpatterns = [
    path('', ProductListView.as_view(), name='home'),
    path('products/<int:pk>/', ProductDetailView.as_view(), name='product_detail'),
    path('contacts/', ContactsView.as_view(), name='contacts'),
]