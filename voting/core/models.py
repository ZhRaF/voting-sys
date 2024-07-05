from django.db import models
from django.contrib.auth.models import User

class Election(models.Model):
    id_election = models.AutoField(primary_key=True)
    subject = models.TextField()
    start_date = models.DateField()
    end_date = models.DateField()

    def __str__(self):
        return self.subject


class Candidate(models.Model):
    id_candidate = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    points = models.PositiveIntegerField(default=0)
    election = models.ForeignKey(Election, on_delete=models.CASCADE,related_name='candidates')

    def __str__(self):
        return f"Candidate {self.user.username} in {self.election.subject}"

class Vote(models.Model):
    id_vote = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(auto_now_add=True) 
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE,related_name='votes')
    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'candidate__election'], name='unique_vote_per_election')
        ]
    def __str__(self):
        return f"Vote by {self.user} in {self.election}"

class DemandCandidature(models.Model):
    id_demand_candidature = models.AutoField(primary_key=True)
    status = models.BooleanField(default=False)
    election = models.ForeignKey(Election, on_delete=models.CASCADE, related_name='demand_candidatures')
    date = models.DateField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='demand_candidatures')
    motivation = models.TextField()
    def __str__(self):
        return f"Demand by {self.user.username} for {self.election.subject}"
    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'election'], name='unique_demand_per_election')
        ]