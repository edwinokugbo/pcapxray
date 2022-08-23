# Generated by Django 4.1 on 2022-08-20 16:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('xray', '0010_packet_dst_port_packet_src_port'),
    ]

    operations = [
        migrations.CreateModel(
            name='Pcap',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(null=True)),
                ('date_uploaded', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]