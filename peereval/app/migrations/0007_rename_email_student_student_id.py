# Generated by Django 5.1.3 on 2024-11-30 08:34

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0006_alter_student_email_alter_student_uid'),
    ]

    operations = [
        migrations.RenameField(
            model_name='student',
            old_name='email',
            new_name='student_id',
        ),
    ]
