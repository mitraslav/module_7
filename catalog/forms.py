# catalog/forms.py
from django import forms
from django.core.exceptions import ValidationError
from decimal import Decimal, InvalidOperation
from products_proj.models import Product

FORBIDDEN_WORDS = (
    'казино', 'криптовалюта', 'крипта', 'биржа', 'дешево',
    'бесплатно', 'обман', 'полиция', 'радар'
)

MAX_IMAGE_SIZE = 5 * 1024 * 1024
ALLOWED_CONTENT_TYPES = ('image/jpeg', 'image/png')


class ProductForm(forms.ModelForm):
    class Meta:
        model = Product

        fields = ['name', 'description', 'img', 'category', 'price_for_unit']
        labels = {
            'price_for_unit': 'Цена'
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


        for name, field in self.fields.items():
            widget = field.widget
            # checkbox (Boolean) — класс bootstrap для чекбокса
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs.update({'class': 'form-check-input'})
            else:
                # остальные поля — form-control
                existing = widget.attrs.get('class', '')
                widget.attrs.update({'class': (existing + ' form-control').strip()})

            # placeholder = label (опционально)
            if not widget.attrs.get('placeholder'):
                widget.attrs['placeholder'] = field.label

    # проверка имени
    def clean_name(self):
        name = self.cleaned_data.get('name', '')
        lower = name.lower()
        for w in FORBIDDEN_WORDS:
            if w in lower:
                raise ValidationError(f'Поле имя содержит запрещённое слово: "{w}"')
        return name

    # проверка описания
    def clean_description(self):
        description = self.cleaned_data.get('description', '') or ''
        lower = description.lower()
        for w in FORBIDDEN_WORDS:
            if w in lower:
                raise ValidationError(f'Поле описание содержит запрещённое слово: "{w}"')
        return description

    # валидация цены
    def clean_price_for_unit(self):
        price = self.cleaned_data.get('price_for_unit')
        if price is None:
            return price
        try:
            if Decimal(price) < 0:
                raise ValidationError('Цена не может быть отрицательной.')
        except (ValueError, TypeError, InvalidOperation):
            raise ValidationError('Введите корректное числовое значение цены.')
        return price


    clean_price = clean_price_for_unit

    # валидация изображения
    def clean_img(self):
        img = self.cleaned_data.get('img')
        if img:
            ct = getattr(img, 'content_type', None)
            if ct not in ALLOWED_CONTENT_TYPES:
                raise ValidationError('Разрешены только форматы JPEG и PNG.')
            if img.size > MAX_IMAGE_SIZE:
                raise ValidationError('Максимальный размер изображения 5 МБ.')
        return img
