from users.apps import UsersConfig
from django.urls import path
from .views import RegisterView, CustomLoginView, LogoutView, ProfileView
from django.contrib.auth.views import LogoutView as AuthLogoutView

app_name = UsersConfig.name

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', AuthLogoutView.as_view(next_page='products_proj:home'), name='logout'),
    path('profile/', ProfileView.as_view(), name='profile'),
]