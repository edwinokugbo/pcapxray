import os

from django import forms
from django.conf import settings

from .models import Default


class DefaultForm(forms.ModelForm):
    """ Form for managing default settings """
    class Meta:
        model = Default
        fields = ['output_dir', 'show_unknown_protocols', 'theme', 'skip_old_report', 'edge_width']
