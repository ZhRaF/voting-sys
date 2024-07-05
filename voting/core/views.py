from django.contrib import messages
from django.forms import ValidationError
from django.http import Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
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
from django.contrib.auth.models import Group
from .models import *
from .forms import *
from datetime import date



group, created = Group.objects.get_or_create(name='Condidates')

def user_admin_required(view_func):

    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_superuser:
            return HttpResponseForbidden("You are not authorized to access this page.")
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view


def signup(request):

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

    if request.method =="POST":
        username=request.POST["username"]
        password=request.POST["password"]

        user = authenticate(request, username=username, password=password)
        if user is not None: 
            login(request,user)
            messages.success(request, "You have successfully logged in.")
            return redirect("listElections")

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
    return redirect("signin")


@user_admin_required
def add_election(request):
    if request.method == 'POST':
        form = ElectionForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('listElectionsAdmin')  
    else:
        form = ElectionForm()

    return render(request, 'addElection.html', {'form': form})

@user_admin_required
def list_elections_admin(request):
    election_data=[]
    elections=Election.objects.all()
    for e in elections:
        demands=e.demand_candidatures.count()
        election_data.append({
            'election':e,
            'number_demands':demands  } )
    return render(request,"listElectionsAdmin.html",{"election_data":election_data})

@user_admin_required
def election_demands(request,id):
    election=Election.objects.get(id_election=id)
    print('coco')
    demands=election.demand_candidatures.all()
    print(demands)
    return render(request,"electionDemands.html",{"demands":demands})

@user_admin_required

def accept_demand(request, id):
    demand = get_object_or_404(DemandCandidature, id_demand_candidature=id)
    
    if request.method == 'POST':
        demand.status = True
        demand.save()
        
        Candidate.objects.create(user=demand.user, election=demand.election)
        
        user = demand.user
        group, created = Group.objects.get_or_create(name='Candidates')
        user.groups.add(group)
        
        messages.success(request, 'The new candidate has been successfully added')
        return redirect('listElections')
    else:
        return render(request, 'acceptDemand.html', {'demand': demand})
@user_admin_required
def list_users(request):
    users=User.objects.all()
    return render(request, 'listUsers.html',{'users':users})

# ::::::::::::::::::::::
@login_required
def list_elections(request):
    elections_data = []
    current_date = date.today()
    elections = Election.objects.all()

    for e in elections:
        vote = False
        if e.end_date <= current_date:
            vote = True
        
        demand_candidature = False
        if e.start_date > current_date:
            demand_candidature = True
        
        elections_data.append({
            'election': e,
            'vote': vote,
            'demand_candidature': demand_candidature
        })
    
    return render(request, 'listElections.html', {'elections_data': elections_data})

@login_required
def vote_election(request, id_election):
    election = get_object_or_404(Election, id_election=id_election)
    candidates = election.candidates.all()
    return render(request, 'voteElection.html', {'candidates': candidates, 'id_election': id_election})
@login_required
def add_vote(request, id_user, id_election):
    if request.method == 'POST':
        selected_candidate = request.POST.get('selected_candidate')
        if selected_candidate:
            candidate = get_object_or_404(Candidate, id_candidate=selected_candidate)
            candidate.points += 1
            candidate.save()
            Vote.objects.create(user_id=id_user, candidate=candidate)
            messages.success(request, "Your vote has been successfully added")
            return redirect("resultsElection", id_election=id_election)
        else:
            messages.error(request, "No candidate selected. Please select a candidate to vote.")
            return redirect("voteElection", id_election=id_election)
    else:
        return redirect('listElections')
    
def results_election(request, id_election):
    try:
        election = Election.objects.get(id_election=id_election)
        candidates = Candidate.objects.filter(election=election)

        total_votes = 0
        results_data = []

        for candidate in candidates:
            total_votes += Vote.objects.filter(candidate=candidate).count()

        if total_votes == 0:
            total_votes = 1

        for candidate in candidates:
            candidate_votes = Vote.objects.filter(candidate=candidate).count()
            if total_votes == 0:
                result=0
            else:
                result = (candidate_votes / total_votes) * 100

            results_data.append({
                'candidate': candidate,
                'result': result
            })

        return render(request, 'resultElection.html', {'election': election, 'results_data': results_data})

    except Election.DoesNotExist:
        return render(request, 'error.html', {'message': 'Election not found'})

    except Exception as e:
        return render(request, 'error.html', {'message': str(e)})


from django.db import IntegrityError
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import DemandCandidature, Election
from .forms import DemandCandidatureForm

@login_required
def demand_candidature(request, id_election):
    election = Election.objects.get(id_election=id_election)

    if request.method == 'POST':
        form = DemandCandidatureForm(request.POST)
        if form.is_valid():
            demand_candidature = form.save(commit=False)
            demand_candidature.election = election
            demand_candidature.user = request.user
            try:
                demand_candidature.save()
                messages.success(request, "Your demand has been successfully submitted.")
                return redirect('listElections')
            except IntegrityError:
                messages.error(request, "You have already submitted a demand for this election.")
        else:
            messages.error(request, "Form submission failed. Please check the details.")
    else:
        form = DemandCandidatureForm()

    return render(request, 'demandCandidature.html', {'form': form, 'election': election})
