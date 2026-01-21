import os
from dotenv import load_dotenv
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.core.mail import send_mail
from .models import BlogPost


load_dotenv()

class BlogPostListView(ListView):
    model = BlogPost
    template_name = 'blogs/post_list.html'
    context_object_name = 'posts'
    paginate_by = 10

    def get_queryset(self):
        # возвращаем только опубликованные
        return BlogPost.objects.filter(is_published=True).order_by('-created_at')

class BlogPostDetailView(DetailView):
    model = BlogPost
    template_name = 'blogs/post_detail.html'
    context_object_name = 'post'

    def get_object(self, queryset=None):
        obj = super().get_object(queryset=queryset)
        # увеличиваем счетчик просмотров
        obj.views = (obj.views or 0) + 1
        obj.save(update_fields=['views'])
        # Доп. задание: при достижении 100 просмотров отправлять письмо
        if obj.views == 100:
            send_mail(
                subject=f'Статья "{obj.title}" достигла 100 просмотров',
                message=f'Поздравляем! Статья "{obj.title}" набрала 100 просмотров.',
                from_email=None,  # использует DEFAULT_FROM_EMAIL
                recipient_list=[ 'your_email@example.com' ],  # замените на свой адрес
            )
        return obj

class BlogPostCreateView(CreateView):
    model = BlogPost
    fields = ['title', 'content', 'preview', 'is_published']
    template_name = 'blogs/post_form.html'

class BlogPostUpdateView(UpdateView):
    model = BlogPost
    fields = ['title', 'content', 'preview', 'is_published']
    template_name = 'blogs/post_form.html'

    def get_success_url(self):
        # перенаправление на страницу отредактированной статьи
        return self.object.get_absolute_url()

class BlogPostDeleteView(DeleteView):
    model = BlogPost
    template_name = 'blogs/post_confirm_delete.html'
    success_url = '/'  # или reverse_lazy('blogs:post_list')