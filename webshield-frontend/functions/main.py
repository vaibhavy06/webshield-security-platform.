import sys
import os
from mangum import Mangum

# Allow importing the 'app' module from the current directory
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.main import app

# Serverless handler for Netlify
handler = Mangum(app, lifespan="off")
