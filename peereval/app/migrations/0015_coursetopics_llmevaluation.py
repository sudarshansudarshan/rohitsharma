# Generated by Django 5.1.3 on 2024-12-01 14:49

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0014_remove_peerevaluation_count_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CourseTopics',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('topic', models.CharField(blank=True, max_length=200, null=True)),
                ('date', models.DateTimeField(auto_now_add=True)),
                ('prof', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='LLMEvaluation',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('feedback', models.TextField()),
                ('score', models.IntegerField()),
                ('date', models.DateTimeField(auto_now_add=True)),
                ('CourseTopic', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.coursetopics')),
                ('student', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]