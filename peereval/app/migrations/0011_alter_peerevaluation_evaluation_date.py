# Generated by Django 5.1.3 on 2024-11-30 16:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0010_numberofquestions'),
    ]

    operations = [
        migrations.AlterField(
            model_name='peerevaluation',
            name='evaluation_date',
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]