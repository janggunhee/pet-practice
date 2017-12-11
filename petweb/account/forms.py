from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.template import loader

from .models import User, UserManager

User = get_user_model()

class UserCreationForm(forms.ModelForm):
    # 사용자 생성 폼
    email = forms.EmailField(
        label='Email',
        required=True,
        widget=forms.EmailInput(
            attrs={
                'class': 'form-control',
                'placeholder': '이메일 주소',
                'required': 'True'
            }
        )
    )
    nickname = forms.CharField(
        label='Nickname',
        required=True,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': '닉네임',
                'required': 'True'
            }
        )
    )
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': '패스워드',
                'required': 'True',
            }
        )
    )
    password2 = forms.CharField(
        label='Password confirmation',
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': '패스워드 확인',
                'required': 'True',
            }
        )
    )

    class Meta:
        model = User
        fields = ('email', 'nickname')

    def clean_password2(self):
        # 두 비밀번호 입력 일치 확인
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError('패스워드가 일치하지 않습니다')
        return password2

    def save(self, commit=True):
        # 제공된 패스워드를 해쉬값으로 저장
        user = super(UserCreationForm, self).save(commit=False)
        user.email = UserManager.normalize_email(self.cleaned_data['email'])
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    # 비밀번호 변경 폼
    password = ReadOnlyPasswordHashField(
        label='Password'
    )

    class Meta:
        model = User
        fields = ('email', 'password', 'is_active', 'is_superuser')

    def clean_password(self):
        return self.initial['password']

# class PasswordResetForm(forms.Form):
#     email = forms.EmailField(label='Email', max_length=254)
#
#     def send_mail(self, subject_template_name, email_template_name,
#                     context, form_email, html_email_template_name=None):
#         """
#         django.core.mail.EmailMultiAlternatives를 'to_email'로 보냅니다.
#         """
#         subject = loader.render_to_string(subject_template_name, context)
#         subject = ''.join(subject.splitline())
#         body = loader.render_to_string(email_template_name, context)
#
#         email_message = EmailMultiAlternatives(subject, body, form_email, ['to_email'])
#         if html_email_template_name is not None:
#             html_email = loader.render_to_string(html_email_template_name, context)
#             email_message.attach_alternative(html_email, 'text/html')
#
#         email_message.send()
#
#     def get_users(self, email):
#         active_users = get_user_model()._default_namager.filter(
#             email__iexact=email, is_active=True)
#         return (u for u in active_users if u.has_usable_password())
#
#     def save(self, domain_override=None,
#              subject_template_name='registration/password_reset_subject.txt',
#              email_template_name='registration/password_reset_email.html',
#              use_https=False, token_generator=default_token_generator,
#              from_email=None, request=None, html_email_template_name=None,
#              extra_email_context=None):
#         """
#         비밀번호 재설정을 위한 1 회만 사용 가능한 링크를 생성하고 사용자에게 보낸다
#         """
#
#         email =self.cleaned_data['email']
#         for user in self.get_users(email):
#             if not domain_override:
#                 current_site = get_current_site(request)
#                 site_name = current_site.name
#                 domain = current_site.domain
#             else:
#                 site_name = domain = domain_override
#             context = {
#                 'email': user.email,
#                 'domain': domain,
#                 'site_name': site_name,
#                 'uid': user,
#                 'token': token_generator.make_token(user),
#                 'protocol': 'https' if use_https else 'http',
#             }
#             if extra_email_context is not None:
#                 context.update(extra_email_context)
#             self.send_mail(
#                 subject_template_name, email_template_name, context, from_email,
#                 user.email, html_email_template_name=html_email_template_name,
#             )
#
# class SetpasswordForm():
#




