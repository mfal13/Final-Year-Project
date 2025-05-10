from flask import Flask, render_template, request
import os
from scanner import main  # Import your scanning function

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    message = ''
    scan_output = ''

    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(file_path)

            try:
                scan_output = main(file_path)  # capture output from scanner
                message = f"✅ File '{uploaded_file.filename}' scanned successfully!"
            except Exception as e:
                message = f"❌ Error scanning file: {str(e)}"

    return render_template('index.html', message=message, result=scan_output)


if __name__ == '__main__':
    app.run(debug=True)
