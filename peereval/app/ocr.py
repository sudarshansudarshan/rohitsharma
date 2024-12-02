from pdf2image import convert_from_bytes
from PIL import Image
import pytesseract
import io
import re
from django.core.files.uploadedfile import InMemoryUploadedFile

def is_number(s):
    try:
        float(s)  # Try converting to a float
        return True
    except ValueError:
        return False

def crop_top_left(image, crop_width, crop_height):
    left = 0
    top = 0
    right = crop_width
    bottom = crop_height
    return image.crop((left, top, right, bottom))

def process_uploaded_pdf(uploaded_file):
    try:
        # Convert the uploaded PDF to an image
        pdf_bytes = uploaded_file.read()
        images = convert_from_bytes(pdf_bytes, first_page=1, last_page=1)

        if not images:
            raise Exception("Failed to convert PDF to images")

        # Process the first page
        image = images[0]
        crop_width = int(image.width * 0.2)
        crop_height = int(image.height * 0.1)

        # Crop the top-left corner
        cropped_image = crop_top_left(image, crop_width, crop_height)

        # Perform OCR on the cropped image
        recognised_text = pytesseract.image_to_string(cropped_image, config='--psm 6')

        # Extract a number from the OCR text
        extracted_number = re.search(r'\b\d{3}\b', recognised_text)
        if not extracted_number:
            raise Exception("No number found in OCR output")

        number = extracted_number.group()

        # Rename the PDF in-memory
        new_pdf_filename = f"{number}.pdf"
        renamed_file = io.BytesIO(pdf_bytes)
        renamed_file.seek(0)

        # Wrap the renamed file with InMemoryUploadedFile
        wrapped_file = InMemoryUploadedFile(
            renamed_file,
            field_name="file",
            name=new_pdf_filename,
            content_type="application/pdf",
            size=len(pdf_bytes),
            charset=None
        )
        return int(number.strip()), wrapped_file

    except Exception as e:
        print(f"Error processing uploaded PDF: {e}")
        raise