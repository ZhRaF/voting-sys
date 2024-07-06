from django.urls import path
from . import views

urlpatterns = [
    path('signup',views.signup,name='signup'),
    path('',views.signin,name='signin'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),  
    path('signout',views.signout,name='signout'),
    path('addElection/', views.add_election, name='addElection'),
    path('listElectionsAdmin/', views.list_elections_admin, name='listElectionsAdmin'),
    path('electionDemands/<int:id>', views.election_demands, name='electionDemands'),
    path('acceptDemand/<int:id>', views.accept_demand, name='acceptDemand'),
    path('listElections/', views.list_elections, name='listElections'),
    path('listUsers/', views.list_users, name='listUsers'),
    path('vote/<int:id_election>', views.vote_election, name='voteElection'),
    path('addVote/<int:id_election>/', views.add_vote, name='addVote'),
    path('resultsElection/<int:id_election>/',views.results_election, name='resultsElection'),
    path('demandCandidature/<int:id_election>/',views.demand_candidature, name='demandCandidature'),
    path('listDemandCandidature/',views.list_demand_candidature, name='listDemandCandidature'),
    path('deleteDemand/<int:id_demand>/', views.delete_demand, name='deleteDemand'),


    ]