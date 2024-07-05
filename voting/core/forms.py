from django import forms
from .models import *

class ElectionForm(forms.ModelForm):
    class Meta:
        model = Election
        fields = ['subject', 'start_date', 'end_date']
        widgets = {
            'start_date': forms.DateInput(attrs={'type': 'date'}),
            'end_date': forms.DateInput(attrs={'type': 'date'}),
        }

class DemandCandidatureForm(forms.ModelForm):
    class Meta:
        model = DemandCandidature
        fields = ['motivation']
        widgets = {
            'motivation': forms.Textarea(attrs={'rows': 4, 'cols': 15}),
        }