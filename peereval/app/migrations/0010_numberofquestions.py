# Generated by Django 5.1.3 on 2024-11-30 10:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0009_userprofile'),
    ]

    operations = [
        migrations.CreateModel(
            name='numberOfQuestions',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('number', models.IntegerField()),
            ],
        ),
    ]
