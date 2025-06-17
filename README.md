# URL Scanner

A Flask web application that analyzes URLs for potential security threats using pattern matching and the VirusTotal API.

## Features

- Real-time URL scanning
- Pattern-based analysis for suspicious URLs
- Integration with VirusTotal API
- Clear and user-friendly interface
- Scan history logging in SQLite database
- REST API endpoint for programmatic access

## Prerequisites

- Python 3.8 or higher
- VirusTotal API key

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd url-scanner
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root and add your VirusTotal API key:
```
VT_API_KEY=your_api_key_here
```

## Usage

1. Start the Flask application:
```bash
python app.py
```

2. Open your web browser and navigate to `http://localhost:5000`

3. Enter a URL in the input field and click "Scan"

## API Usage

The application provides a REST API endpoint for programmatic access:

```bash
curl -X POST http://localhost:5000/api/scan \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```

## Security Considerations

- The application uses environment variables to store sensitive information
- All user input is validated and sanitized
- API keys are never exposed to the client
- HTTPS is recommended for production deployment

## License

MIT License 