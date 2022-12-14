# Generated by Django 4.1 on 2022-09-10 13:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('xray', '0022_default_skip_old_report'),
    ]

    operations = [
        migrations.AddField(
            model_name='default',
            name='edge_width',
            field=models.IntegerField(choices=[(1, '1'), (2, '2'), (3, '3'), (4, '4'), (5, '5'), (10, '10'), (15, '15'), (20, '20')], default=1),
        ),
        migrations.AlterField(
            model_name='default',
            name='theme',
            field=models.IntegerField(choices=[(0, 'Dark'), (1, 'Light'), (2, 'Grey')], default=0),
        ),
    ]
