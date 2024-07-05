from django.db import models
from django.contrib.auth.models import User

class Election(models.Model):
    id_election = models.AutoField(primary_key=True)
    subject = models.TextField()
    start_date = models.DateField()
    end_date = models.DateField()

    def __str__(self):
        return self.subject

class Vote(models.Model):
    id_vote = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(auto_now_add=True) 
    election = models.ForeignKey(Election, on_delete=models.CASCADE)

    def __str__(self):
        return f"Vote by {self.user} in {self.election}"

class Candidate(models.Model):
    id_candidate = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    points = models.PositiveIntegerField(default=0)
    election = models.ForeignKey(Election, on_delete=models.CASCADE)

    def __str__(self):
        return f"Candidate {self.user.username} in {self.election.subject}"
    
class DemandCandidature(models.Model):
    status = models.BooleanField(default=False)
    election = models.ForeignKey(Election, on_delete=models.CASCADE, related_name='demand_candidatures')
    date = models.DateField(auto_now_add=True) 
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='demand_candidatures')

    def __str__(self):
        return f"Demand by {self.user.username} for {self.election.subject}"

