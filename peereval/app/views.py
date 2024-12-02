from django.http import JsonResponse
from django.shortcuts import render
# Import necessary modules and models
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .models import *
from app.ocr import process_uploaded_pdf
import os
from math import sqrt, ceil
from random import shuffle
from collections import defaultdict

# NOTE: This is admn dashboard
from math import sqrt, ceil, floor
from random import shuffle
from collections import defaultdict
import string
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import requests
import google.generativeai as genai
import json
import base64

genai.configure(api_key="AIzaSyBrat_wDHdrOGboCJfT-mYhyD_dpqipsbM")

def geminiGenerate(prompt):
    model = genai.GenerativeModel('gemini-1.5-pro')
    response = model.generate_content(prompt)
    return response.text


def parse_llama_json(text):
    # Extract JSON part from the generated text
    start_idx = text.find('{')
    end_idx = text.rfind('}') + 1

    if start_idx == -1 or end_idx == -1:
        raise ValueError("No valid JSON found in the text")

    json_part = text[start_idx:end_idx]

    # Parse the extracted JSON
    try:
        parsed_data = json.loads(json_part)
        return parsed_data
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON: {e}")


def evaluate_answers(answer1, answer2, topic):
    prompt = f"""
    The topic of discussion was: """ + topic + """. I want to evaluate the following student answers:
    
    **Task:** As an AI Assistant, assess the answers provided based on their originality, quality, and relevance to the topic. Also, evaluate the percentage of AI-generated content in the answers. Provide the output in **JSON format** with the following structure:
    
    **Evaluation Criteria:**
    1. **Score (0 to 10):** Reflects the quality, depth, and relevance of the answer.
    2. **AI Plagiarism Score (0 to 1):** Indicates the likelihood of the content being AI-generated or plagiarized from online sources.

    **Expected JSON Response Format:**
    ```json
    {
        "question 1": {
            "score": <quality_score_between_0_to_10>,
            "ai": <ai_plagiarism_score_between_0_to_10>,
            "feedback": "<optional_feedback_message>"
        },
        "question 2": {
            "score": <quality_score_between_0_to_10>,
            "ai": <ai_plagiarism_score_between_0_to_10>
            "feedback": "<optional_feedback_message>"
        }
    }
    ```
    
    **Student Answers:**
    - Question 1: """ + answer1 + """
    - Question 2: """ + answer2 + """

    Ensure the response strictly follows the JSON format and provides clear scores for each answer.
    """

    scores = parse_llama_json(geminiGenerate(prompt))

    # Calculate aggregate score (penalizing AI plagiarism)
    aggregate_score = (
        (scores['question 1']['score'] * (1 - scores['question 1']['ai'])) +
        (scores['question 2']['score'] * (1 - scores['question 2']['ai']))
    )/2

    # Return the aggregate results
    return {
        "aggregate_score": round(aggregate_score, 2),
        "answers": " ".join([answer1, answer2]),
        "feedback": " ".join([scores['question 1']['feedback'], scores['question 2']['feedback']]),
        "ai_scores": [scores['question 1']['ai'], scores['question 2']['ai']],
        "scores": [scores['question 1']['score'], scores['question 2']['score']]
    }

# Secret key for encryption and decryption (You should keep this key secret)
SECRET_KEY = "MySuperSecretKey"

def xor_encrypt_decrypt(data, key):
    """
    XOR Encryption and Decryption function.
    Encrypts and decrypts by XOR-ing each byte of the data with the key.
    """
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key[i % len(key)])
    return bytes(result)

def encode_id(document_id):
    """
    Encrypts the document ID using XOR and then encodes it in base64 for URL safety.
    """
    # Convert document_id to a byte string
    doc_id_bytes = str(document_id).encode('utf-8')

    # Encrypt using XOR with the secret key
    encrypted_bytes = xor_encrypt_decrypt(doc_id_bytes, SECRET_KEY.encode('utf-8'))

    # Encode the encrypted bytes to base64 for URL safety
    encoded = base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
    return encoded

def decode_id(encoded_str):
    """
    Decodes the document ID by reversing the XOR encryption and base64 decoding.
    """
    # Decode from base64
    encrypted_bytes = base64.urlsafe_b64decode(encoded_str)

    # Decrypt using XOR with the secret key
    decrypted_bytes = xor_encrypt_decrypt(encrypted_bytes, SECRET_KEY.encode('utf-8')).decode('utf-8')

    # Convert the decrypted bytes back to string and return as integer
    document_id, evaluator_id = decrypted_bytes.split(" ")

    return int(document_id), int(evaluator_id)


def AdminDashboard(request):
    # Check if the user has a role that allows file uploads (Admin only)
    user_profile = UserProfile.objects.filter(user=request.user).first()
    if not user_profile or user_profile.role != 'Admin' or not request.user.is_authenticated:
        messages.error(request, 'Permission denied')
        return redirect('/login/')

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        user = User.objects.get(username=request.user)
        docs = request.FILES.getlist('doc')  # Get multiple uploaded files

        document_instances = []
        document_peer_map = defaultdict(int)  # Track the number of peers assigned to each document

        for doc in docs:
            # Process each uploaded PDF
            uid, processed_doc = process_uploaded_pdf(doc)

            # Ensure the student exists
            student = Student.objects.filter(uid=uid).first()
            if not student:
                continue

            # Create and save the document object
            document = documents(
                title=title,
                description=description,
                user_id=user,
                uid=student,
                file=processed_doc
            )
            # Generate the peer evaluation link using the encoded document ID
            document.save()
            document_instances.append(document)

        # Assign peer evaluations
        num_peers = floor(sqrt(len(document_instances)))
        all_students = list(Student.objects.all())
        shuffle(all_students)

        # Create a distribution map to track how many evaluations each student can still review
        student_distribution = {
            student.uid: num_peers for student in all_students
        }

        # Duplicate document list to ensure each document is considered multiple times
        document_instances = document_instances * num_peers
        shuffle(document_instances)

        peer_evaluations_assigned = defaultdict(int)  # Tracks evaluations per document

        for document in document_instances:
            for student in all_students:
                if (
                    student.uid != document.uid.uid  # Avoid assigning a student to their own document
                    and student_distribution[student.uid] > 0  # Ensure the student can still evaluate more
                    and peer_evaluations_assigned[document.id] < num_peers  # Ensure the document gets enough reviewers
                ):
                    # Assign evaluation
                    PeerEvaluation.objects.create(
                        evaluator_id=student.uid,
                        evaluation_date=None,  # Placeholder
                        evaluation=[],  # Placeholder
                        feedback=[],  # Placeholder
                        score=0,  # Placeholder
                        document=document,
                    )
                    email = User.objects.get(pk=student.student_id_id).email
                    student_distribution[student.uid] -= 1
                    peer_evaluations_assigned[document.id] += 1
                    encoded_doc_id = encode_id(str(document.id) + " " + str(student.uid))
                    evaluation_link = f"http://127.0.0.1:8000/studentEval/{encoded_doc_id}/"
                    send_peer_evaluation_email(evaluation_link, email)
                    break  # Move to the next document once assigned to a student
            
        messages.success(request, 'Documents uploaded and peer evaluations assigned successfully!')
        return redirect('/AdminHome/')

    return render(request, 'AdminDashboard.html', {'users': user_profile.serialize()})


# NOTE: This is TA dashboard
def TAHome(request):

    # Check if the user has a role that allows file uploads (Admin only)
    user_profile = UserProfile.objects.filter(user=request.user).first()
    if not user_profile or user_profile.role != 'TA' or not request.user.is_authenticated:
        messages.error(request, 'Permission denied')
        return redirect('/logout/')

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        user = User.objects.get(username=request.user)
        docs = request.FILES.getlist('doc')  # Get multiple uploaded files

        document_instances = []
        student_document_map = defaultdict(list)  # Map to track documents by student UID

        for doc in docs:
            # Process each uploaded PDF
            uid, processed_doc = process_uploaded_pdf(doc)

            # Ensure the student exists
            student = Student.objects.filter(uid=uid).first()
            if not student:
                continue

            # Create and save the document object
            document = documents(
                title=title,
                description=description,
                user_id=user,
                uid=student,
                file=processed_doc
            )
            document.save()
            document_instances.append(document)
            student_document_map[student.uid].append(document)

        # Assign peer evaluations
        num_docs = len(document_instances)
        num_peers = ceil(sqrt(num_docs))
        all_students = list(Student.objects.all())
        shuffle(all_students)  # Randomize the order of students

        # Assign documents to peers
        for document in document_instances:
            assigned_peers = set()
            for student in all_students:
                if len(assigned_peers) >= num_peers:
                    break
                if student.uid not in assigned_peers and document.uid.uid != student.uid:
                    PeerEvaluation.objects.create(
                        evaluator_id=student.uid,
                        evaluation_date=None,  # To be filled during evaluation
                        evaluation='',  # Placeholder
                        feedback='',  # Placeholder
                        score=0,  # Placeholder
                        document=document,
                        count = num_peers
                    )
                    assigned_peers.add(student.uid)

        messages.success(request, 'Documents uploaded and peer evaluations assigned successfully!')
        return redirect('/TAHome/')

    # Last added topic
    last_topic = CourseTopics.objects.last()
    return render(request, 'TAHome.html', {'users': user_profile.serialize(), 'topic': last_topic.topic})


# NOTE: This is Teacher dashboard
def TeacherHome(request):
    # Check if the user has a role that allows file uploads (TA, Teacher, Admin)
    user_profile = UserProfile.objects.filter(user=request.user).first()
    if not user_profile or user_profile.role != 'Teacher' or not request.user.is_authenticated:
        messages.error(request, 'You do not have permission to upload files.')
        return redirect('/login/')

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        user = User.objects.get(username=request.user)
        docs = request.FILES.getlist('doc')  # Get multiple uploaded files

        for doc in docs:
            # Process each uploaded PDF
            uid, processed_doc = process_uploaded_pdf(doc)

            # Ensure the student exists
            student = Student.objects.filter(uid=uid).first()
            if not student:
                continue

            # Create and save the document object
            document = documents(
                title=title,
                description=description,
                user_id=user,
                uid=student,
                file=processed_doc
            )
            document.save()

        messages.success(request, 'Documents uploaded successfully!')
        return redirect('/AdminHome/')

    return render(request, 'TeacherHome.html')


# NOTE: This is route for uploading bunch of PDF Files
def uploadFile(request):
    if request.method == 'POST':
        file = request.FILES.get('csv-upload')
        file_data = file.read().decode("utf-8")
        file_data = file_data.strip()
        lines = file_data.split("\n")

        # Remove the first row (header)
        lines.pop(0)

        # Delete all existing Student and document records
        documents.objects.all().delete()
        Student.objects.all().delete()

        for line in lines:
            if line:
                data = line.split(",")
                try:
                    # Get or create User instance
                    user, created = User.objects.get_or_create(
                        email=data[1],
                        defaults={
                            'username': data[1].split("@")[0],
                            'first_name': data[0].split()[0],
                            'last_name': data[0].split()[1] if len(data[0].split()) > 1 else '',
                        }
                    )
                    if created:
                        user.set_password("Abcd@1234")
                        user.save()

                    # Create or update Student record
                    Student.objects.update_or_create(
                        student_id=User.objects.get(email=data[1]),
                        defaults={'uid': data[2]}
                    )
                except Exception as e:
                    print(f"Error processing line: {line} - {e}")
                    continue

        messages.info(request, 'Students uploaded successfully!')
        return redirect('/AdminHome/')
    return render(request, 'uploadFile.html')


# NOTE: This is route for logging in
def login_page(request):
    # Check if the HTTP request method is POST (form submission)
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Check if a user with the provided username exists
        if not User.objects.filter(username=username).exists():
            # Display an error message if the username does not exist
            messages.error(request, 'Invalid Username')
            return redirect('/login/')
        
        # Authenticate the user with the provided username and password
        user = authenticate(username=username, password=password)
        
        if user is None:
            # Display an error message if authentication fails (invalid password)
            messages.error(request, "Invalid Password")
            return redirect('/login/')
        else:
            user_profile = UserProfile.objects.filter(user=user).first()
            if user_profile.role == "Admin":
                login(request, user)
                return redirect('/AdminHome/')
            elif user_profile.role == "TA":
                login(request, user)
                return redirect('/TAHome/')
            elif user_profile.role == "Teacher":
                login(request, user)
                return redirect('/TeacherHome/')
            elif user_profile.role == "Student":
                login(request, user)
                return redirect('/StudentHome/')
            login(request, user)
            return redirect('/AdminHome/')
    
    # Render the login page template (GET request)
    return render(request, 'login.html')


# Define a view function for the registration page
def register_page(request):
    # Check if the HTTP request method is POST (form submission)
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        password = request.POST.get('password')
        roll_no = request.POST.get('roll_no')

        print(first_name, last_name, username, password, roll_no)
        
        # Check if a user with the provided username already exists
        user = User.objects.filter(username=username)
        
        if user.exists():
            # Display an information message if the username is taken
            messages.info(request, "Username already taken!")
            return redirect('login/')
        
        # Create a new User object with the provided information
        user = User.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            username=username
        )
        
        # Set the user's password and save the user object
        user.set_password(password)
        user.save()
        
        # Display an information message indicating successful account creation
        messages.info(request, "Account created Successfully!")
        return redirect('/register/')
    
    # Render the registration page template (GET request)
    return render(request, 'register.html')



def evaluationList(request):
    docs = []
    for doc in documents.objects.all():
        evaluations = PeerEvaluation.objects.filter(document_id=doc.id)
        docs.append({
            'doc': doc,
            'evaluations': evaluations
        })
    return render(request, 'docs.html', {'docs': docs})


# NOTE: This is route for uploading CSV file
def uploadCSV(request):
    # Check if the user has a role that allows file uploads (Admin only)
    user_profile = UserProfile.objects.filter(user=request.user).first()
    if not user_profile or user_profile.role not in ["TA", "Admin", "Teacher"] or not request.user.is_authenticated:
        messages.error(request, 'Permission denied')
        return redirect('/logout/')

    if request.method == 'POST':
        file = request.FILES.get('csv-upload')
        file_data = file.read().decode("utf-8")
        file_data = file_data.strip()
        lines = file_data.split("\n")

        # Remove the first row (header)
        lines.pop(0)

        # Delete all existing Student and document records
        documents.objects.all().delete()
        Student.objects.all().delete()
        PeerEvaluation.objects.all().delete()

        for line in lines:
            if line:
                data = line.split(",")
                try:
                    # Get or create User instance
                    user, created = User.objects.get_or_create(
                        email=data[1],
                        defaults={
                            'username': data[1].split("@")[0],
                            'first_name': data[0].split()[0],
                            'last_name': data[0].split()[1] if len(data[0].split()) > 1 else '',
                        }
                    )
                    if created:
                        user.set_password("Abcd@1234")
                        user.save()

                    # Create or update Student record
                    Student.objects.update_or_create(
                        student_id=User.objects.get(email=data[1]),
                        defaults={'uid': data[2]}
                    )
                except Exception as e:
                    print(f"Error processing line: {line} - {e}")
                    continue

        messages.info(request, 'Students uploaded successfully!')
        return redirect('/AdminHome/')
    return redirect('/AdminHome/')


# TODO: Working fine but getting status code 302
def change_role(request):

    if request.method == 'POST':
        current_user_profile = UserProfile.objects.filter(user=request.user).first()
        if not current_user_profile or current_user_profile.role not in ['TA', 'Teacher', 'Admin']:
            messages.error(request, 'You do not have permission to modify roles.')
            return redirect('/AdminHome/')

        try:
            user = User.objects.get(username=request.POST.get('username'))
            user_profile = UserProfile.objects.filter(user_id=user.id).first()
            if not user_profile:
                user_profile = UserProfile(user_id=user.id, role=request.POST.get('role'))
                user_profile.save()
            else:
                user_profile.role = request.POST.get('role')
                user_profile.save()

            messages.success(request, f"Role for {user.username} updated.")
        except User.DoesNotExist:
            messages.error(request, 'User not found.')

    return redirect('/AdminHome/')


# NOTE: Update number of questions in particular test
def questionNumbers(request):
    if request.method == 'POST':
        number = request.POST.get('num-questions')
        numQue = numberOfQuestions.objects.filter(id=1).first()
        if not numQue:
            numQue = numberOfQuestions(number=number)
        else:
            numQue.number = number
        numQue.save()
        messages.success(request, 'Number of questions updated successfully!')
        return redirect('/AdminHome/')
    return render(request, 'questionNumbers.html')


# NOTE: Change password route
def changePassword(request):
    if request.method == 'POST':
        user = User.objects.get(username=request.user)
        user.set_password(request.POST.get('password'))
        user.save()
        messages.error(request, 'Password changed')
        return redirect('/logout/')
    return render(request, 'changePassword.html')


def studentHome(request):

    # Check if the user has a role that allows file uploads (Admin only)
    user_profile = UserProfile.objects.filter(user=request.user).first()
    if not user_profile or not request.user.is_authenticated:
        messages.error(request, 'Permission denied')
        return redirect('/logout/')

    # Get the logged-in user's student profile
    student_profile = Student.objects.filter(student_id=request.user).first()

    if not student_profile:
        return JsonResponse({'error': 'Student profile not found'}, status=404)

    # Fetch the documents where the student is an evaluator
    evaluation_files = PeerEvaluation.objects.filter(evaluator_id=student_profile.uid).select_related('document')

    # Fetch documents submitted by the student for which peer reviews are available
    own_documents = documents.objects.filter(uid=student_profile.uid).prefetch_related('peer_evaluations')

    # Prepare data to send to the template
    evaluation_files_data = [
        {
            'document_title': eval_file.document.title,
            'description': eval_file.document.description,
            'file_url': f"/studentEval/{encode_id(eval_file.document.id)}"  # Hides original URL
        }
        for eval_file in evaluation_files
    ]

    own_documents_data = [
        {
            'document_title': doc.title,
            'description': doc.description,
            'peer_reviews': [
                {
                    'evaluator_id': review.evaluator_id,
                    'evaluation': review.evaluation,
                    'feedback': review.feedback,
                    'score': review.score,
                }
                for review in doc.peer_evaluations.all()
            ]
        }
        for doc in own_documents
    ]
    # Last added topic
    last_topic = CourseTopics.objects.last()

    # Return data in JSON format to the Jinja template
    return render(request, 'studentHome.html', {
        'evaluation_files': evaluation_files_data,
        'own_documents': own_documents_data,
        'topic': last_topic.topic
    })


# NOTE: View and evaluate the assignment
def studentEval(request, eval_id):

    document_id, evaluator_id = decode_id(eval_id)
    document = documents.objects.filter(id=document_id).first()
    evaluation = PeerEvaluation.objects.filter(document_id=document_id, evaluator_id=evaluator_id).first()


    # Check if the user has a role that allows file uploads (Admin only)
    user_profile = UserProfile.objects.filter(user=request.user).first()
    if not user_profile or not request.user.is_authenticated or not evaluation or evaluation.evaluated or not document:
        messages.error(request, 'Permission denied')
        return redirect('/logout/')

    number_of_questions = numberOfQuestions.objects.filter(id=1).first().number
    # Prepare data to pass to the template, including the document URL

    context = {
        'document_url': document.file.url,  # Assuming the 'file' field stores the document file
        'document_title': document.title,
        'document_description': document.description,
        'number_of_questions': [i+ 1 for i in range(number_of_questions)]
    }

    if request.method == 'POST':
        evaluations = []
        feedback = []
        for i in range(1, number_of_questions+1):
            if request.POST.get(f'question-{i}'):
                evaluations.append(int(request.POST.get(f'question-{i}')))
            else:
                evaluations.append(0)

            if request.POST.get(f'feedback-{i}'):
                feedback.append(request.POST.get(f'feedback-{i}'))
            else:
                feedback.append('')
        
        # Sum of all evaluations
        total_marks = sum(evaluations)
        current_evaluation = PeerEvaluation.objects.filter(document_id=document_id, evaluator_id=evaluator_id).update(
            evaluation=evaluations,
            feedback=feedback,
            score=total_marks,
            evaluated=True
        )
        current_evaluation.save()


        messages.error(request, 'Evaluation submitted successfully!')
    
    # Render the template and pass the document URL and other details
    return render(request, 'AssignmentView.html', context)


# NOTE: Send email to the assigned peer
def send_peer_evaluation_email(evaluation_link, email_id):
    """
    Sends a peer evaluation email to the assigned peer with an HTML template.
    """
    subject = "Peer Evaluation Request"
    
    # Render the HTML template
    html_message = render_to_string(
        "EvalMailTemplate.html",  # Path to your email template
        {
            "evaluation_link": evaluation_link,  # Link to the evaluation
        },
    )
    plain_message = strip_tags(html_message)  # Fallback plain text version
    
    # Send the email
    send_mail(
        subject=subject,
        message=plain_message,
        from_email="no-reply@evaluation-system.com",
        recipient_list=[email_id],
        html_message=html_message,  # Attach the HTML message
        fail_silently=False,
    )


# NOTE: Associate topic
def associateTopic(request):
    # Check if the user has a role that allows file uploads (Admin only)
    user_profile = UserProfile.objects.filter(user=request.user).first()
    if not user_profile or user_profile.role not in ["TA", "Admin", "Teacher"] or not request.user.is_authenticated:
        messages.error(request, 'Permission denied')
        return redirect('/logout/')

    if request.method == 'POST':
        topic = request.POST.get('topic')
        topic = CourseTopics(
            topic=topic,
            prof=User.objects.get(username=request.user)
        )
        topic.save()

        messages.success(request, 'Topic added successfully!')
        return redirect('/TAHome/')


#NOTE: Evaluate the answers with LLM
def evaluateAnswers(request):
    # Ensure the user is authenticated and has a valid profile
    user_profile = UserProfile.objects.filter(user=request.user).first()
    if not user_profile or not request.user.is_authenticated:
        messages.error(request, 'Permission denied')
        return redirect('/logout/')

    if request.method == 'POST':
        # Get answers from POST request
        answer1 = request.POST.get('answer1', '').strip()
        answer2 = request.POST.get('answer2', '').strip()

        if not answer1 or not answer2:
            messages.error(request, 'Both answers are required.')
            return redirect('/StudentHome/')

        # Get the latest topic
        topic = CourseTopics.objects.last()
        if not topic:
            messages.error(request, 'No topic available for evaluation.')
            return redirect('/StudentHome/')

        if LLMEvaluation.objects.filter(CourseTopic=topic, student=request.user).exists():
            messages.error(request, 'You have already evaluated this topic.')
            return redirect('/StudentHome/')

        try:
            # Evaluate answers
            evaluated_results = evaluate_answers(answer1, answer2, topic.topic)

            # Save evaluation results to the database
            LLMEvaluation.objects.create(
                CourseTopic=topic,
                student=request.user,
                answer=evaluated_results["answers"],
                feedback=evaluated_results["feedback"],
                score=evaluated_results["scores"],
                ai=evaluated_results["ai_scores"],
                aggregate=evaluated_results["aggregate_score"]
            )

            messages.success(request, 'Evaluation submitted successfully!')
        except Exception as e:
            messages.error(request, f"An error occurred during evaluation: {e}")
            return redirect('/StudentHome/')

    return redirect('/StudentHome/')

def TeacherHome(request):
    return render(request, 'TeacherHome.html')

def logout_user(request):
    logout(request)
    return redirect('/login/')