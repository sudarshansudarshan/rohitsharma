# Generated by Django 5.1.3 on 2024-12-01 15:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0016_llmevaluation_answer'),
    ]

    operations = [
        migrations.AddField(
            model_name='llmevaluation',
            name='ai',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
    ]