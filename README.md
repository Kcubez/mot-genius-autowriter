# Gemini Facebook Scheduler

## Overview

The Gemini Facebook Scheduler is a web application that allows users to generate content using Google Gemini and schedule posts to a Facebook page. The application features a user-friendly interface built with HTML and styled using Tailwind CSS.

## Features

- Content generation using Google Gemini
- Scheduling posts to a Facebook page
- Responsive design with Tailwind CSS
- Simple and intuitive user interface

## Technologies Used

- **Backend**: Python with Flask
- **Frontend**: HTML, Tailwind CSS, JavaScript
- **APIs**: Google Gemini API, Facebook Graph API

## Project Structure

```
gemini-facebook-scheduler
├── app.py                # Main backend application
├── requirements.txt      # Python dependencies
├── static
│   ├── css
│   │   └── style.css     # Custom styles using Tailwind CSS
│   └── js
│       └── main.js       # Frontend JavaScript code
├── templates
│   └── index.html        # Main HTML template
├── package.json          # npm configuration file
├── tailwind.config.js    # Tailwind CSS configuration
└── README.md             # Project documentation
```

## Setup Instructions

1. **Clone the repository**:

   ```
   git clone <repository-url>
   cd gemini-facebook-scheduler
   ```

2. **Set up a Python virtual environment**:

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Python dependencies**:

   ```
   pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   Create a `.env` file in the root directory and add your configuration:

   ```
   # Flask Configuration
   FLASK_SECRET_KEY=your-very-secret-key-here

   # Google Gemini API
   GEMINI_API_KEY=your-gemini-api-key-here

   # Admin User Configuration
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=your-secure-admin-password-here

   # PostgreSQL Database Configuration (required)
   DATABASE_URL=your-postgresql-database-url-here
   ```

5. **Configure API keys**:
   - Obtain API keys for Google Gemini and Facebook Graph API.
   - Set the keys in your environment variables or directly in the `app.py` file.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any suggestions or improvements.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
