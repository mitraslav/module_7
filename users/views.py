# users/views.py
from django.urls import reverse_lazy
from django.views.generic import CreateView, TemplateView, UpdateView
from django.contrib.auth import login
from django.core.mail import send_mail
from django.shortcuts import redirect
from .forms import RegistrationForm, EmailAuthenticationForm
from .models import User
from django.contrib.auth.views import LoginView, LogoutView

class RegisterView(CreateView):
    model = User
    form_class = RegistrationForm
    template_name = 'users/register.html'
    success_url = reverse_lazy('products_proj:home')

    def form_valid(self, form):
        response = super().form_valid(form)
        # автоматически авторизуем пользователя
        login(self.request, self.object)
        # отправка приветственного письма
        send_mail(
            subject='Добро пожаловать в наш магазин',
            message=f'Здравствуйте, {self.object.username}! Спасибо за регистрацию.',
            from_email=None,
            recipient_list=[self.object.email],
        )
        return response


class CustomLoginView(LoginView):
    form_class = EmailAuthenticationForm
    template_name = 'users/login.html'

class ProfileView(UpdateView):
    model = User
    fields = ('username','avatar','phone','country')
    template_name = 'users/profile.html'
    success_url = reverse_lazy('products_proj:home')

    def get_object(self):
        return self.request.user
