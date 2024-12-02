'''
from pdf2image import convert_from_bytes
from PIL import Image
import pytesseract
import re
import io
from googleapiclient.discovery import build
from google.oauth2.service_account import Credentials
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

SCOPE = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/spreadsheets",
]
CREDENTIALS_FILE = "peer-evaluation-440806-5b8bd496fe1e.json"

# Authenticate Google Drive
def authenticate_drive():
    creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=SCOPE)
    service = build('drive', 'v3', credentials=creds)
    return service

# Crop the top left corner of the image
def crop_top_left(image, crop_width, crop_height):
    left = 0
    top = 0
    right = crop_width
    bottom = crop_height
    return image.crop((left, top, right, bottom))

# Get PDF content from Google Drive without downloading
def get_pdf_from_drive(service, file_id):
    request = service.files().get_media(fileId=file_id)
    pdf_content = io.BytesIO()
    downloader = MediaIoBaseDownload(pdf_content, request)

    done = False
    while not done:
        status, done = downloader.next_chunk()
        print(f"Download {int(status.progress() * 100)}%.")

    pdf_content.seek(0)  # Move to the beginning of the stream
    return pdf_content

# Extract name from the top-left corner of the first page
def name_extraction(service, folder_id, file_id, pdf_filename):
    try:
        pdf_content = get_pdf_from_drive(service, file_id)
        images = convert_from_bytes(pdf_content.read())
        print(f"Successfully converted PDF to images. Number of pages: {len(images)}")
    except Exception as e:
        print(f"Error converting PDF to images: {e}")
        return

    if not images:
        raise Exception("Failed to convert PDF to images")

    image = images[0]  # Only the first page is processed
    crop_width = int(image.width * 0.2)
    crop_height = int(image.height * 0.1)

    cropped_image = crop_top_left(image, crop_width, crop_height)

    recognised_text = pytesseract.image_to_string(cropped_image, config='--psm 6')

    extracted_name = re.findall(r'\b\d{3}\b', recognised_text)
    text = "".join(extracted_name)

    if text:
        new_pdf_filename = f"{text}.pdf"
        print("Extracted name for renaming:", new_pdf_filename)
    else:
        print("No valid name extracted, keeping the original filename.")
        new_pdf_filename = pdf_filename

    # Re-upload the renamed PDF to Google Drive
    upload_pdf(service, folder_id, pdf_content, new_pdf_filename)

    # Delete the original PDF file
    delete_pdf(service, file_id)

# Upload the renamed file back to Google Drive without saving it locally
def upload_pdf(service, folder_id, pdf_content, new_filename):
    pdf_content.seek(0)  # Reset the stream position before uploading
    file_metadata = {
        'name': new_filename,
        'parents': [folder_id]
    }
    media = MediaIoBaseUpload(pdf_content, mimetype='application/pdf')
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"Uploaded renamed file as {new_filename}. File ID: {file.get('id')}")

# Function to delete the original PDF file
def delete_pdf(service, file_id):
    try:
        service.files().delete(fileId=file_id).execute()
        print(f"Deleted original PDF file with ID: {file_id}")
    except Exception as e:
        print(f"Error deleting file: {e}")

# Main function to process PDFs in the Google Drive folder
def process_pdfs_in_folder(folder_id):
    service = authenticate_drive()

    # List PDF files in the folder
    query = f"'{folder_id}' in parents and mimeType='application/pdf'"
    results = service.files().list(q=query, fields="files(id, name)").execute()
    files = results.get('files', [])

    if not files:
        raise Exception("No PDF files found in the specified folder")

    # Process each PDF file
    for file in files:
        file_id = file['id']
        pdf_filename = file['name']
        print(f"Processing file: {pdf_filename}")
        name_extraction(service, folder_id, file_id, pdf_filename)

# Example usage
#folder_id = '1fT-inciLQut85BGEQrjMSWbVRcTsdWfQ'  # Replace with your Google Drive folder ID
#process_pdfs_in_folder(folder_id)

'''

from pdf2image import convert_from_bytes
from PIL import Image
import pytesseract
import re
import io
from googleapiclient.discovery import build
from google.oauth2.service_account import Credentials
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

SCOPE = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/spreadsheets",
]
CREDENTIALS_FILE = "peer-evaluation-440806-5b8bd496fe1e.json"

# Authenticate Google Drive
def authenticate_drive():
    creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=SCOPE)
    service = build('drive', 'v3', credentials=creds)
    return service

# Crop the top left corner of the image
def crop_top_left(image, crop_width, crop_height):
    left = 0
    top = 0
    right = crop_width
    bottom = crop_height
    return image.crop((left, top, right, bottom))

# Get PDF content from Google Drive without downloading
def get_pdf_from_drive(service, file_id):
    request = service.files().get_media(fileId=file_id)
    pdf_content = io.BytesIO()
    downloader = MediaIoBaseDownload(pdf_content, request)

    done = False
    while not done:
        status, done = downloader.next_chunk()
        print(f"Download {int(status.progress() * 100)}%.")

    pdf_content.seek(0)  # Move to the beginning of the stream
    return pdf_content

# Extract name from the top-left corner of the first page
def name_extraction(service, folder_id, file_id, pdf_filename):
    try:
        pdf_content = get_pdf_from_drive(service, file_id)
        images = convert_from_bytes(pdf_content.read())
        #print(f"Successfully converted PDF to images. Number of pages: {len(images)}")
    except Exception as e:
        #print(f"Error converting PDF to images: {e}")
        return False

    if not images:
        raise Exception("Failed to convert PDF to images")
        return False

    image = images[0]  # Only the first page is processed
    crop_width = int(image.width * 0.2)
    crop_height = int(image.height * 0.1)

    cropped_image = crop_top_left(image, crop_width, crop_height)

    recognised_text = pytesseract.image_to_string(cropped_image, config='--psm 6')

    extracted_name = re.findall(r'\b\d{3}\b', recognised_text)
    text = "".join(extracted_name)

    if text:
        new_pdf_filename = f"{text}.pdf"
        #print("Extracted name for renaming:", new_pdf_filename)
    else:
        #print("No valid name extracted, keeping the original filename.")
        new_pdf_filename = pdf_filename

    # Re-upload the renamed PDF to Google Drive
    status = upload_pdf(service, folder_id, pdf_content, new_pdf_filename)

    # Delete the original PDF file
    status2 = delete_pdf(service, file_id)
    if status and status2:
        return True
    else:
        return False

# Upload the renamed file back to Google Drive without saving it locally
def upload_pdf(service, folder_id, pdf_content, new_filename):
    pdf_content.seek(0)  # Reset the stream position before uploading
    file_metadata = {
        'name': new_filename,
        'parents': [folder_id]
    }
    media = MediaIoBaseUpload(pdf_content, mimetype='application/pdf')
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    #print(f"Uploaded renamed file as {new_filename}. File ID: {file.get('id')}")
    return True

# Function to delete the original PDF file
def delete_pdf(service, file_id):
    try:
        service.files().delete(fileId=file_id).execute()
        return True
        #print(f"Deleted original PDF file with ID: {file_id}")
    except Exception as e:
        #print(f"Error deleting file: {e}")
        return False

# Main function to process PDFs in the Google Drive folder
def process_pdfs_in_folder(folder_id):
    count = 0
    service = authenticate_drive()

    # List PDF files in the folder
    query = f"'{folder_id}' in parents and mimeType='application/pdf'"
    results = service.files().list(q=query, fields="files(id, name)").execute()
    files = results.get('files', [])

    if not files:
        #raise Exception("No PDF files found in the specified folder")
        return count

    # Process each PDF file
    for file in files:
        file_id = file['id']
        pdf_filename = file['name']
        #print(f"Processing file: {pdf_filename}")
        status = name_extraction(service, folder_id, file_id, pdf_filename)
        if status:
            count = count + 1

    return count
