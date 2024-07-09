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
import logging
from django.db import IntegrityError
logger = logging.getLogger(__name__)

# --------------------------------------- admin ------------------------------------


group, created = Group.objects.get_or_create(name='Condidates')

def user_admin_required(view_func):
    """
    Decorator to ensure the user is a superuser.

    Parameters:
    view_func (function): The view function to be wrapped.

    Returns:
    function: The wrapped view function with access check.
    """
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_superuser:
            return HttpResponseForbidden("You are not authorized to access this page.")
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view



def signup(request):
    """
    Handle user signup, including validation, creation, and email confirmation.

    Parameters:
    request (HttpRequest): The request object.

    Returns:
    HttpResponse: Redirect to the signin page or render the signup template.
    """
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
                logger.error(f'Signup failed for {username}: {error}')
            return redirect('signup')

        if password1 != password2:
            messages.error(request, 'Passwords do not match')
            logger.error(f'Signup failed for {username}: Passwords do not match')
            return redirect('signup')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            logger.error(f'Signup failed for {username}: Username already exists')
            return redirect('signup')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists')
            logger.error(f'Signup failed for {username}: Email already exists')
            return redirect('signup')

        user = User.objects.create_user(username, email, password1)
        user.first_name = fname
        user.last_name = lname
        user.is_active = False
        user.save()

        messages.success(request, 'Your account has been successfully created. We have sent you a confirmation email.')
        logger.info(f'User created: {username}, email: {email}')

        subject = 'Welcome to Voting System'
        message1 = f'Hello {username},\nWelcome to Voting System'
        from_email = settings.EMAIL_HOST_USER
        to_list = [user.email]
        send_mail(subject, message1, from_email, to_list, fail_silently=True)

        current_site = get_current_site(request)
        email_subject = 'Confirm your email'
        message2 = render_to_string('authentication/emailConfirmation.html', {
            'name': user.username,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user),
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            to=[user.email]
        )
        email.send()
        logger.info(f'Confirmation email sent to {user.email}')

        return redirect('signin')

    return render(request, 'authentication/signup.html')

def activate(request, uidb64, token):
    """
    Activate a user's account using the activation link.

    Parameters:
    request (HttpRequest): The request object.
    uidb64 (str): Base64 encoded user ID.
    token (str): Activation token.

    Returns:
    HttpResponse: Redirect to the signin page or raise Http404 if invalid.
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        logger.error(f'Activation failed: {e}')
        raise Http404("Invalid activation link")

    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        messages.success(request, "Your account has been activated!")
        logger.info(f'User {user.username} activated and logged in')
        return redirect('signin')
    else:
        logger.error(f'Invalid activation link for user with uid {uid}')
        raise ValidationError("Invalid activation link.")

def signin(request):
    """
    Handle user login and redirect based on user type.

    Parameters:
    request (HttpRequest): The request object.

    Returns:
    HttpResponse: Render the signin template or redirect to appropriate page after login.
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "You have successfully logged in.")
            logger.info(f'User {username} logged in successfully')
            if request.user.is_superuser:
                return redirect("listElectionsAdmin")
            else:
                return redirect("listElections")
        else:
            if not User.objects.filter(username=username).exists():
                messages.error(request, "Incorrect username")
                logger.error(f'Login failed for {username}: Incorrect username')
            else:
                messages.error(request, "Incorrect password")
                logger.error(f'Login failed for {username}: Incorrect password')

    return render(request, "authentication/signin.html")

@login_required
def signout(request):
    """
    Handle user logout and redirect to the signin page.

    Parameters:
    request (HttpRequest): The request object.

    Returns:
    HttpResponse: Redirect to the signin page.
    """
    logout(request)
    messages.success(request, "You have successfully logged out.")
    logger.info(f'User {request.user.username} logged out successfully')
    return redirect("signin")

# --------------------------------------admin-------------------------------

@user_admin_required
def add_election(request):
    """
    Handle the creation of a new election.

    If the request method is POST, validate and save the submitted form data.
    If the form is valid, redirect to the list of elections for admins.

    Parameters:
    request (HttpRequest): The request object containing form data.

    Returns:
    HttpResponse: Redirect to 'listElectionsAdmin' if form is valid, or render the 'addElection.html' template.
    """
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
    """
    Display a list of all elections with the number of demands for each election.

    Retrieves all election records and counts the number of demands for each election.
    Passes this data to the 'listElectionsAdmin.html' template.

    Parameters:
    request (HttpRequest): The request object.

    Returns:
    HttpResponse: Render the 'listElectionsAdmin.html' template with election data.
    """
    election_data = []
    elections = Election.objects.all()
    for e in elections:
        demands = e.demand_candidatures.count()
        election_data.append({
            'election': e,
            'number_demands': demands
        })
    return render(request, "listElectionsAdmin.html", {"election_data": election_data})

@user_admin_required
def election_demands(request, id):
    """
    Display the demands (candidatures) for a specific election.

    Retrieves all demands associated with the election identified by the given ID.
    Passes the demands to the 'electionDemands.html' template for rendering.

    Parameters:
    request (HttpRequest): The request object.
    id (int): The ID of the election to retrieve demands for.

    Returns:
    HttpResponse: Render the 'electionDemands.html' template with the list of demands.
    """
    election=Election.objects.get(id_election=id)
    demands=election.demand_candidatures.all()
    return render(request,"electionDemands.html",{"demands":demands})

@user_admin_required
def accept_demand(request, id):
    """
    Accept a demand and create a candidate.

    Updates the status of the demand identified by the given ID to accepted (True),
    and creates a new candidate associated with the demand's user and election.

    Parameters:
    request (HttpRequest): The request object.
    id (int): The ID of the demand to be accepted.

    Returns:
    HttpResponse: Redirects to the 'electionDemands' view for the associated election after processing,
                  or renders the 'acceptDemand.html' template if the request method is not POST.
    """
    demand = get_object_or_404(DemandCandidature, id_demand_candidature=id)
    id_election = demand.election.id_election

    if request.method == 'POST':
        demand.status = True
        demand.save()

        Candidate.objects.create(
            user=demand.user,
            election=demand.election
        )
        messages.success(request, 'The new candidate has been successfully added.')

        return redirect('electionDemands', id=id_election)
    else:
        return render(request, 'acceptDemand.html', {'demand': demand})
    
@user_admin_required
def list_users(request):
    """
    List all users excluding the admin.

    Retrieves all user instances from the database, excluding the superuser (admin), 
    and renders them in the 'listUsers.html' template.

    Parameters:
    request (HttpRequest): The request object.

    Returns:
    HttpResponse: The rendered 'listUsers.html' template with a context containing
                  the list of users.
    """
    admin = User.objects.get(is_superuser=True)
    users = User.objects.all().exclude(id=admin.id)
    return render(request, 'listUsers.html', {'users': users})

# --------------------------------------- normal user------------------------------------
def user_required(view_func):
    """
    Decorator to ensure the user is not a superuser.

    Parameters:
    view_func (function): The view function to be wrapped.

    Returns:
    function: The wrapped view function with access check.
    """
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_superuser:
            return HttpResponseForbidden("Access denied. This page is only for normal users.")
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view

@login_required
@user_required
def list_elections(request):
    """
    List all elections with voting and demand candidature status.

    Retrieves all election instances from the database and determines the voting and 
    demand candidature status based on the current date. 
    Renders the list of elections with their respective statuses in the 'listElections.html' template.

    Parameters:
    request (HttpRequest): The request object.

    Returns:
    HttpResponse: The rendered 'listElections.html' template with a context containing
                  election data and their voting and demand candidature statuses.
    """
    elections_data = []
    current_date = date.today()
    elections = Election.objects.all()

    for e in elections:
        vote = False
        if (e.end_date >= current_date) and (e.start_date <= current_date):
            vote = True
        
        demand_candidature = False
        if e.start_date > current_date and e.end_date > current_date:
            demand_candidature = True



        print(f'demand_candidature{demand_candidature}')
         
        elections_data.append({
            'election': e,
            'vote': vote,
            'demand_candidature': demand_candidature
        })
    
    return render(request, 'listElections.html', {'elections_data': elections_data})

@login_required
@user_required
def vote_election(request, id_election):
    """
    Display the candidates for a specific election to allow the user to make a vote.

    Retrieves the election instance and its associated candidates based on the provided
    election ID. Renders the candidates in the 'voteElection.html' template.

    Parameters:
    request (HttpRequest): The request object.
    id_election (int): The ID of the election for which candidates are to be listed.

    Returns:
    HttpResponse: The rendered 'voteElection.html' template with a context containing
                  the candidates and election ID.
    """
    election = get_object_or_404(Election, id_election=id_election)
    candidates = election.candidates.all()
    return render(request, 'voteElection.html', {'candidates': candidates, 'id_election': id_election})

@login_required
@user_required
def add_vote(request, id_election):
    """
    Add a vote to a candidate in a specific election.

    Retrieves the election and checks if the user has already voted. If not, processes the vote
    for the selected candidate, creates a new Vote object, and updates the candidate's points.
    Handles errors and logs messages accordingly.

    Parameters:
    request (HttpRequest): The request object.
    id_election (int): The ID of the election in which the user is voting.

    Returns:
    HttpResponse: Redirects to the results page of the election if successful, or
                  back to the voting page with an error message if unsuccessful.
    """
    try:
        election = get_object_or_404(Election, id_election=id_election)
        votes = Vote.objects.filter(election=election).select_related('user')
        voters = [vote.user for vote in votes]

        if request.user in voters:
            messages.error(request, "You have already voted in this election.")
            logger.warning(f'User {request.user.id} attempted to vote again in election {id_election}.')
            return redirect('resultsElection', id_election=id_election)
        
        selected_candidate = request.POST.get('selected_candidate')
        
        if selected_candidate:
            try:
                candidate = get_object_or_404(Candidate, id_candidate=selected_candidate)
                candidate.points += 1
                candidate.save()
                Vote.objects.create(user_id=request.user.id, candidate=candidate, election=election)
                messages.success(request, "Your vote has been successfully added")
                logger.info(f'User {request.user.id} voted for candidate {candidate.id_candidate} in election {id_election}')
                return redirect("resultsElection", id_election=id_election)
            except Exception as e:
                messages.error(request, "An error occurred while processing your vote.")
                logger.error(f'Error while processing vote for candidate {selected_candidate} by user {request.user.id}: {e}', exc_info=True)
                return redirect("voteElection", id_election=id_election)
        else:
            messages.error(request, "No candidate selected. Please select a candidate to vote.")
            logger.warning(f'User {request.user.id} did not select a candidate for election {id_election}')
            return redirect("voteElection", id_election=id_election)

    except Exception as e:
        logger.error(f'Unexpected error in add_vote view: {e}', exc_info=True)
        messages.error(request, "An unexpected error occurred. Please try again later.")
        return redirect("voteElection", id_election=id_election)


@login_required
@user_required
def results_election(request, id_election):
    """
    Display the results of a specific election.

    Retrieves the election and calculates the voting results for each candidate. Renders the results
    in the 'resultsElection.html' template.

    Parameters:
    request (HttpRequest): The request object.
    id_election (int): The ID of the election for which results are being displayed.

    Returns:
    HttpResponse: The rendered 'resultsElection.html' template with the election and results data.
    """
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

        return render(request, 'resultsElection.html', {'election': election, 'results_data': results_data})

    except Election.DoesNotExist:
        messages.error(request,"election not found")
        return render(request, 'listElections.html')
    
@login_required
@user_required
def demand_candidature(request, id_election):
    """
    Submit a demand to become a candidate for a specific election.

    Retrieves the election and handles the form submission to create a demand for candidature. 
    Handles errors and logs messages accordingly.

    Parameters:
    request (HttpRequest): The request object.
    id_election (int): The ID of the election for which the demand is being submitted.

    Returns:
    HttpResponse: Redirects to the list of elections if successful, or back to the demand page
                  with an error message if unsuccessful.
    """
    try:
        election = Election.objects.get(id_election=id_election)
    except Election.DoesNotExist:
        logger.error(f'Election with id {id_election} does not exist.')
        messages.error(request, "The election does not exist.")
        return redirect('listElections')

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
                logger.error(f'IntegrityError: User {request.user.id} has already submitted a demand for election {id_election}.')
                messages.error(request, "You have already submitted a demand for this election.")
            except Exception as e:
                logger.error(f'Unexpected error occurred: {e}', exc_info=True)
                messages.error(request, "An unexpected error occurred. Please try again later.")
        else:
            logger.warning('Form submission failed due to invalid data.')
            messages.error(request, "Form submission failed. Please check the details.")
    else:
        form = DemandCandidatureForm()

    return render(request, 'demandCandidature.html', {'form': form, 'election': election})

@login_required
@user_required
def list_demand_candidature(request):
    """
    List all demands for candidature submitted by the logged-in user.

    Retrieves all demands for candidature submitted by the currently logged-in user and renders
    them in the 'listDemandCandidature.html' template.

    Parameters:
    request (HttpRequest): The request object.

    Returns:
    HttpResponse: The rendered 'listDemandCandidature.html' template with the user's demands.
    """
    user=User.objects.get(id=request.user.id)
    demands=user.demand_candidatures.all()
    return render(request, 'listDemandCandidature.html', {'demands':demands})

@login_required
@user_required
def delete_demand(request, id_demand):
    """
    Delete a specific demand for candidature submitted by the logged-in user.

    Retrieves the demand and deletes it if it has not been accepted. Handles errors and logs
    messages accordingly.

    Parameters:
    request (HttpRequest): The request object.
    id_demand (int): The ID of the demand to be deleted.

    Returns:
    HttpResponse: Redirects to the list of demands if successful or displays an error message.
    """
    demand = get_object_or_404(DemandCandidature, id_demand_candidature=id_demand, user=request.user)
    if demand.status:
        messages.error(request, 'Accepted demands cannot be deleted.')
    else:
        if request.method == 'POST':
            demand.delete()
            messages.success(request, 'Demand deleted successfully.')
    return redirect('listDemandCandidature')