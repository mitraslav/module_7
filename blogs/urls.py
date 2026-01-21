from django.urls import path
from .views import BlogPostListView, BlogPostDetailView, BlogPostCreateView, BlogPostUpdateView, BlogPostDeleteView
from .apps import BlogsConfig

app_name = BlogsConfig.name

urlpatterns = [
    path('', BlogPostListView.as_view(), name='post_list'),
    path('create/', BlogPostCreateView.as_view(), name='post_create'),
    path('<int:pk>/', BlogPostDetailView.as_view(), name='post_detail'),
    path('<int:pk>/edit/', BlogPostUpdateView.as_view(), name='post_edit'),
    path('<int:pk>/delete/', BlogPostDeleteView.as_view(), name='post_delete'),
]