# Generated by Django 4.1 on 2022-08-26 12:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('xray', '0015_default_delete_defaults'),
    ]

    operations = [
        migrations.AddField(
            model_name='default',
            name='output_dir',
            field=models.FilePathField(allow_files=False, allow_folders=True, null=True),
        ),
    ]
