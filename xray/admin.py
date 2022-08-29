from django.contrib import admin
from . import models

# Register your models here.

admin.site.register(models.Packet)
admin.site.register(models.Host)
admin.site.register(models.Default)