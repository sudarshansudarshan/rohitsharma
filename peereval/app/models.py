from django.db import models
from django.contrib.auth.models import User


class numberOfQuestions(models.Model):
    id = models.AutoField(primary_key=True)
    number = models.IntegerField()

    def __str__(self):
        return self.number


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    ROLE_CHOICES = [
        ('TA', 'Teaching Assistant'),
        ('Student', 'Student'),
        ('Teacher', 'Teacher'),
        ('Admin', 'Admin'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)

    def __str__(self):
        return f"{self.user.username} - {self.role}"

    def serialize(self):
        return {
            'id': self.id,
            'username': self.user.username,
            'role': self.role
        }


# Create your models here.
class documents(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=200, blank=True, null=True)
    description = models.TextField(null=True)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    peer_evaluations = models.ManyToManyField('PeerEvaluation')
    uid = models.ForeignKey('Student', on_delete=models.CASCADE)
    file = models.FileField(upload_to='documents/')

    def __str__(self):
        return self.title
    

class Student(models.Model):
    id = models.AutoField(primary_key=True)
    student_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='students')  # Link to User
    uid = models.IntegerField(unique=True)


class PeerEvaluation(models.Model):
    evaluator_id = models.IntegerField()
    evaluation_date = models.DateTimeField(auto_now_add=True)
    evaluation = models.TextField()
    feedback = models.TextField()
    score = models.IntegerField()
    document = models.ForeignKey('documents', on_delete=models.CASCADE)
    evaluated = models.BooleanField(default=False)

    def __str__(self):
        return f'Peer Evaluation for Document {self.document.title}'

# #NOTE: Experimental
# class CourseTopics(models.Model):
#     id = models.AutoField(primary_key=True)
#     topic = models.CharField(max_length=200, blank=True, null=True)
#     date = models.DateTimeField(auto_now_add=True)
#     prof = models.ForeignKey(User, on_delete=models.CASCADE)

#     def __str__(self):
#         return self.topic

# class LLMEvaluation(models.Model):
#     id = models.AutoField(primary_key=True)
#     CourseTopic = models.ForeignKey('CourseTopics', on_delete=models.CASCADE)
#     student = models.ForeignKey(User, on_delete=models.CASCADE)
#     answer = models.TextField()
#     feedback = models.TextField()
#     score = models.TextField()
#     ai = models.TextField()
#     aggregate = models.IntegerField()
#     date = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f'LLM Evaluation for {self.student.username}'