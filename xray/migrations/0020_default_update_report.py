# Generated by Django 4.1 on 2022-09-07 18:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('xray', '0019_tor'),
    ]

    operations = [
        migrations.AddField(
            model_name='default',
            name='update_report',
            field=models.IntegerField(default=0),
        ),
    ]
