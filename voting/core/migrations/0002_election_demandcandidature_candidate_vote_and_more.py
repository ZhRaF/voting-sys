# Generated by Django 5.0.6 on 2024-07-05 20:45

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Election',
            fields=[
                ('id_election', models.AutoField(primary_key=True, serialize=False)),
                ('subject', models.TextField()),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
            ],
        ),
        migrations.CreateModel(
            name='DemandCandidature',
            fields=[
                ('id_demand_candidature', models.AutoField(primary_key=True, serialize=False)),
                ('status', models.BooleanField(default=False)),
                ('date', models.DateField(auto_now_add=True)),
                ('motivation', models.TextField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='demand_candidatures', to=settings.AUTH_USER_MODEL)),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='demand_candidatures', to='core.election')),
            ],
        ),
        migrations.CreateModel(
            name='Candidate',
            fields=[
                ('id_candidate', models.AutoField(primary_key=True, serialize=False)),
                ('points', models.PositiveIntegerField(default=0)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='candidates', to='core.election')),
            ],
        ),
        migrations.CreateModel(
            name='Vote',
            fields=[
                ('id_vote', models.AutoField(primary_key=True, serialize=False)),
                ('date', models.DateField(auto_now_add=True)),
                ('candidate', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='votes', to='core.candidate')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.DeleteModel(
            name='NormalUser',
        ),
    ]
