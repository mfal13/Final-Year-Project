import vt  #Importing VirusTotal API library
import os  #Importing OS for file path manipulations
import hashlib  #Importing hashlib for generating file hashes
import time  #Importing time for adding delays
import magic  #Importing python magic for MIME type detection
import pwd #Importing to retrieve UID
import grp #Importing to retrieve GID

API_KEY = "44cbd23f8e84d9fc60b04a0c5e0b8ea1637b1401293fe7c8061efb696104a97c"  #VirusTotal API key
RATE_LIMIT_SECONDS = 15  #Time delay between requests to avoid hitting the API rate limit
BASE_PATH = "/home/kali/"  #Default file path inputted by the user
UNKNOWN_MIME_LOG = "unknown_mime_types.log"  #Logs the file for unknown MIME types

#Calculate and return the SHA256 hash of the given file
def get_file_hash(file_path):
    sha256 = hashlib.sha256()  #Create a new SHA256 hash object
    with open(file_path, "rb") as file:  #Open the file in binary read mode (rb)
        for block in iter(lambda: file.read(4096), b""):  #Read the file in chunks (4096 bytes)
            sha256.update(block)  #Update the hash with the chunk
    return sha256.hexdigest()  #Return the hexadecimal of the hash

#Upload the file to VirusTotal for scanning and return the report
def upload_file_to_virustotal(client, file_path):
    with open(file_path, "rb") as file:  #Open the file in binary read mode (rb)
        return client.scan_file(file, wait_for_completion=True)  #Scan the file and wait for completion

#Logs the unknown MIME types to a file for future reference
def log_unknown_mime(file_path, mime_type):
    with open(UNKNOWN_MIME_LOG, "a") as log_file:  #Open the log file in append mode (a)
        log_file.write(f"Unknown MIME type for file: {file_path}, Detected MIME: {mime_type}\n")  #Log the details

#Checks if file's actual extension matches its MIME type
def check_file_extension_mismatch(file_path):
    mime = magic.Magic(mime=True)  #Create Magic class to get mime type
    mime_type = mime.from_file(file_path)  #Detects the MIME type of the file

    #Mini database of common MIME types
    mime_extension_map = {
        "application/pdf": "pdf",
        "image/jpeg": "jpg",
        "image/png": "png",
        "application/json": "json",
        "text/plain": "txt",
        "application/zip": "zip",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
        "application/msword": "doc",
        "application/vnd.ms-excel": "xls",
        "application/vnd.ms-powerpoint": "ppt",
        "text/html": "html",
        "text/csv": "csv",
        "audio/mpeg": "mp3",
        "audio/wav": "wav",
        "video/mp4": "mp4",
        "video/x-msvideo": "avi",
        "application/x-tar": "tar",
        "application/x-rar-compressed": "rar",
        "application/x-7z-compressed": "7z",
        "application/x-shockwave-flash": "swf",
        "application/vnd.mozilla.xul+xml": "xul",
        "application/x-java-archive": "jar",
        "application/x-dosexec": "exe",
        "application/octet-stream": "bin",
        "image/gif": "gif",
        "image/bmp": "bmp",
        "image/svg+xml": "svg",
        "image/tiff": "tif",
        "application/x-www-form-urlencoded": "url",
        "text/markdown": "md",
        "application/x-abiword": "abw",
        "application/vnd.oasis.opendocument.text": "odt",
        "application/vnd.oasis.opendocument.spreadsheet": "ods",
        "application/vnd.oasis.opendocument.presentation": "odp",
        "application/vnd.oasis.opendocument.graphics": "odg",
        "application/vnd.ms-fontobject": "eot",
        "application/x-font-ttf": "ttf",
        "application/x-font-opentype": "otf",
        "application/vnd.apple.keynote": "key",
        "application/vnd.apple.pages": "pages",
        "application/vnd.apple.numbers": "numbers",
        "application/vnd.adobe.flash.movie": "flv",
        "video/x-flv": "flv",
        "audio/x-aiff": "aiff",
        "audio/x-flac": "flac",
        "video/ogg": "ogv",
        "audio/ogg": "oga",
        "audio/vnd.dra": "dra",
        "video/x-matroska": "mkv",
        "application/vnd.ms-works": "wps",
        "application/x-dwg": "dwg",
        "application/x-dxf": "dxf",
        "application/vnd.ms-publisher": "pub",
        "application/vnd.mif": "mif",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
        "text/vnd.wap.wml": "wml",
        "text/x-python": "py",
        "text/x-c": "c",
        "text/x-java-source": "java",
    }

    #Get the expected extension based on the detected MIME type
    actual_extension = mime_extension_map.get(mime_type, "unknown")
    file_extension = os.path.splitext(file_path)[-1].lower().lstrip(".")  #Get the file's actual extension

    #Compares the actual extension with the expected extension
    if actual_extension != "unknown":
        if file_extension != actual_extension:  #Check for mismatch
            print(f"Extension mismatch: File has extension '.{file_extension}' but signature suggests '.{actual_extension}'")
            return False  # Mismatch found
        else:
            print(f"File extension and signature match: '.{file_extension}'")
            return True  #Match found
    else:
        print(f"Could not determine file type from signature. Detected MIME: {mime_type}")
        log_unknown_mime(file_path, mime_type)  #Logs the unknown MIME type
        return None  #Return None if the type is still unknown

# Get file creation and modification times
def get_file_times(file_path):
    try:
        # Get the timestamp for file creation and last modification
        creation_time = time.ctime(os.path.getctime(file_path))  # File creation time
        modification_time = time.ctime(os.path.getmtime(file_path))  # File last modification time
        return creation_time, modification_time
    except Exception as e:
        print(f"Error retrieving file times: {e}")
        return None, None

# Gets file owners and permissions
def get_file_owner_permissions(file_path):
    try:
        # Retrieve file owner (user and group)
        file_stat = os.stat(file_path)
        owner = pwd.getpwuid(file_stat.st_uid).pw_name  # User who owns the file
        group = grp.getgrgid(file_stat.st_gid).gr_name  # Group that owns the file

        # Get file permissions but only last 3 characters e.g. 644
        permissions = oct(file_stat.st_mode)[-3:]

        return owner, group, permissions
    except Exception as e: # Error handling code
        print(f"Error retrieving file owner/permissions: {e}")
        return None, None, None

# Gets the files size
def get_file_size(file_path):
    try:
        return os.path.getsize(file_path)  # Returns file size in bytes
    except Exception as e: # Error handlling code
        print(f"Error retrieving file size: {e}")
        return None

from PIL import Image  # Importing the Image class from the Pillow library to work with images
from PIL.ExifTags import TAGS  # Importing TAGS to map EXIF tag values to human-readable names

# Get EXIF data from an image file
def get_image_exif(file_path):
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()  # Extract the EXIF data from the image

        if exif_data is not None:  # Check if the EXIF data exists
            exif_dict = {}  # Empty Dictionary
            for tag, value in exif_data.items():  # Iterate over
                tag_name = TAGS.get(tag, tag)  # Use the TAGS dictionary to get tag name
                exif_dict[tag_name] = value  # Add the tag name to dict

            return exif_dict  # Return the dictionary containing EXIF data
        else:
            print("No EXIF data found.")
            return None

    except Exception as e:  # Error handling code
        print(f"Error retrieving EXIF data: {e}")
        return None

from PyPDF2 import PdfFileReader # Importing PdfFileReader to read and extract information from PDF files
# Get metadata from PDF files
def get_pdf_metadata(file_path):
    try:
        with open(file_path, "rb") as file:
            reader = PdfFileReader(file)
            metadata = reader.getDocumentInfo()  # Extract PDF metadata
            return metadata
    except Exception as e:
        print(f"Error retrieving PDF metadata: {e}")
        return None

#Process the VirusTotal report to show to the user
def process_report(report):
    malicious_sections = {}  #Store malicious detections in dictionary
    if report.last_analysis_stats['malicious'] > 0:  #Checks if there are any malicious detections from VirusTotal report
        print("Malicious content detected!")
        for engine, result in report.last_analysis_results.items():  #Iterate through each analysis result
            if result['category'] == 'malicious':  #Check if the result is malicious
                malicious_sections[engine] = result['result']  #Store the engine(antivirus) and detection result

        print("\nMalicious Detections:")
        for engine, detection in malicious_sections.items():  #Print all detected malicious files
            print(f"- {engine}: {detection}")
    else:
        print("No known malware detected in the file.")  #No malicious files found

# Classifies files into categories based on their MIME type
def classify_file_type(file_path):
    mime = magic.Magic(mime=True)  # Create Magic class to get MIME type
    mime_type = mime.from_file(file_path)  # Detect the MIME type of the file

    # Define file type categories based on MIME type patterns
    file_categories = {
        "image": ["image/jpeg", "image/png", "image/gif", "image/bmp", "image/tiff", "image/svg+xml"],
        "document": ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                     "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     "application/vnd.openxmlformats-officedocument.presentationml.presentation", "text/plain", "application/json"],
        "executable": ["application/x-dosexec", "application/x-executable", "application/x-sharedlib", "application/vnd.microsoft.portable-executable"],
        "archive": ["application/zip", "application/x-tar", "application/x-rar-compressed", "application/x-7z-compressed"],
        "audio": ["audio/mpeg", "audio/wav", "audio/x-aiff", "audio/x-flac"],
        "video": ["video/mp4", "video/x-msvideo", "video/x-matroska", "video/ogg", "video/x-flv"]
    }

    # Classify the file by checking MIME type against categories
    for category, mime_list in file_categories.items():
        if mime_type in mime_list:
            return category

    return "unknown"  # Return "unknown" if MIME type doesn't match any known categories

# Function to print classification result
def classify_and_print_file_type(file_path):
    category = classify_file_type(file_path)  # Classify the file
    print(f"File classified as: {category}")  # Print the classification result

# Main function to execute the scanning process
def main(file_path):
    print("\nFile meta data:")

    # Get file times of creation and modification
    creation_time, modification_time = get_file_times(file_path)
    if creation_time and modification_time:
        print(f"Creation Time: {creation_time}")
        print(f"Modification Time: {modification_time}")

    # Get file owner and permissions
    owner, group, permissions = get_file_owner_permissions(file_path)
    if owner and group and permissions:
        print(f"Owner: {owner}, Group: {group}, Permissions: {permissions}")

    # Get file size
    file_size = get_file_size(file_path)
    if file_size:
        print(f"File Size: {file_size} bytes")

    # Get image EXIF data only if the file is an image
    if file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp')):
        exif_data = get_image_exif(file_path)
        if exif_data:
            print(f"EXIF Data: {exif_data}")

    # Get PDF metadata only if the file is a PDF
    if file_path.lower().endswith('.pdf'):
        pdf_metadata = get_pdf_metadata(file_path)
        if pdf_metadata:
            print(f"PDF Metadata: {pdf_metadata}")

    with vt.Client(API_KEY) as client:  # VirusTotal API client
        is_match = check_file_extension_mismatch(file_path)  # Runs file extension mismatch

        # Print classification after checking file extension mismatch
        if is_match is not None:  # Only print if MIME extension is known
            classify_and_print_file_type(file_path)

        file_hash = get_file_hash(file_path)  # Get the hash of the file
        print(f"File SHA256 Hash: {file_hash}")
        try:
            report = client.get_object(f"/files/{file_hash}")  # Try to get the report from VirusTotal
            print("File scan report found in VirusTotal.")
            process_report(report)  # Process and print the report
        except vt.error.APIError as e:  # If no report found, handle the API error
            print("No existing scan report found. Uploading file for a new scan now")
            report = upload_file_to_virustotal(client, file_path)  # Upload the file for scanning
            print("File scanned successfully. Processing report")
            process_report(report)  # Process the report from the scan

        time.sleep(RATE_LIMIT_SECONDS)  # Sleep to respect rate limits on API

# Code only runs if file run directly
if __name__ == "__main__":
    while True:
        relative_path = input(f"Enter the path to the file (from {BASE_PATH}): ")  # Ask the user for file path
        file_path = os.path.join(BASE_PATH, relative_path)  # Create full file path joining base and user's one

        if os.path.isfile(file_path):  # Checks if the whole path is a valid file
            main(file_path)  # Call the main processing function
            break  # Exit the loop if valid file is provided
        else:
            print("Invalid file path. Please try again.")  # Prompt user to try again

