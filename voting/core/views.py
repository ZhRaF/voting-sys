from django.contrib import messages
from django.forms import ValidationError
from django.http import Http404
from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.decorators import login_required
from django.utils.encoding import force_bytes , force_str
from django.utils.http import urlsafe_base64_decode ,urlsafe_base64_encode
from django.conf import settings
from .tokens import generate_token 
from django.core.mail import send_mail ,EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model




@login_required
def index(request,username):
    return render(request, 'index.html',{"username":username})

def signup(request):
    User=get_user_model()

    if request.method == "POST":
        username = request.POST.get("username")
        fname = request.POST.get("fname")
        lname = request.POST.get("lname")
        email = request.POST.get("email")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        try:
            validate_password(password1)
        except ValidationError as e:
            for error in e.messages:
                messages.error(request, error)
            return redirect('signup')

        if password1 != password2:
            messages.error(request, 'Passwords do not match')
            return redirect('signup')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('signup')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists')
            return redirect('signup')

        user = User.objects.create_user(username, email, password1)
        user.first_name = fname
        user.last_name = lname
        user.is_active = False
        user.save()

        messages.success(request, 'Your account has been successfully created we have sent you a confirmation email')
        # welcm email
        subject = 'app welcome'
        message1 = 'hello '+ username +' \n' 'welcome to voting sys'
        from_email = settings.EMAIL_HOST_USER

        to_list = [user.email]
        send_mail(subject,message1,from_email,to_list,fail_silently=True)
        
        # confirmation email

        current_site = get_current_site(request)
        email_subject = 'confirm your email !'

        message2= render_to_string('authentication/emailConfirmation.html',{     
            'name':user.username,
            'domain':current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)})
        
        email= EmailMessage(
          email_subject,
          message2,
          settings.EMAIL_HOST_USER,
          to=[user.email]

        )
        print('coco')
        email.send()
        
        return redirect('signin')

    return render(request, 'authentication/signup.html')


 
def activate(request, uidb64, token):
    User = get_user_model()

    user = request.user

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        user=None
        raise Http404("Invalid activation link")

    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        messages.success(request, "Votre compte a été activé !")
        return redirect('signin')

    else:
        raise ValidationError("Lien d'activation invalide.")


def signin(request):
    User = get_user_model()

    if request.method =="POST":
        username=request.POST["username"]
        password=request.POST["password"]

        user = authenticate(request, username=username, password=password)
        if user is not None: 
            login(request,user)
            messages.success(request, "You have successfully logged in.")
            return redirect("index", username=username)

        else:
            if not User.objects.filter(username=username).exists(): 
                messages.error(request,"incorrect username")
            else:
                messages.error(request,"incorrect password")


    return render(request , "authentication/signin.html" )



@login_required
def signout(request):
    logout(request)
    messages.success(request, "You have successfully logged out.")
    return redirect("signin" )