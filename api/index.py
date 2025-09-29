import sys
import os

# Add the parent directory to the Python path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Export the Flask app for Vercel
# Vercel expects the WSGI application to be available as a module-level variable
application = app

# For local testing
if __name__ == "__main__":
    app.run(debug=True)
