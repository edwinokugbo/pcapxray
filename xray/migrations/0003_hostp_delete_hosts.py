# Generated by Django 4.1 on 2022-08-19 15:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('xray', '0002_rename_host_hosts'),
    ]

    operations = [
        migrations.CreateModel(
            name='Hostp',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('op', models.CharField(max_length=5, null=True)),
                ('src', models.CharField(max_length=25, null=True)),
                ('dst', models.CharField(max_length=25, null=True)),
            ],
        ),
        migrations.DeleteModel(
            name='Hosts',
        ),
    ]
