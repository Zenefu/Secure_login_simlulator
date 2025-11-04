### This is a little project done during my intern at solution22


 #                SECURE LOGIN SIMULATION


This is a simple Flask web application that demonstrates
a secure user authentication system. It allows users to:

- Sign up and create an account
- Log in securely with hashed passwords
- Access a protected dashboard once logged in


###                 HOW TO RUN THE WEB APP


#### 1. Clone the repository
---------------------------------------------------------------------
   git clone https://github.com/zhen-s22/Secure_login_simlulator.git
   cd Secure-Login-Simulation
---------------------------------------------------------------------

#### 2. Create a virtual environment

   python -m venv venv

   Activate the virtual environment:
   - On Windows:
       venv\Scripts\activate
   - On macOS / Linux:
       source venv/bin/activate


#### 3. Install dependencies

   Make sure you have a requirements.txt file, then run:
       pip install -r requirements.txt


#### 4. Initialize the database

   If the database does not exist yet, run:
       python create_db.py


#### 5. Run the app

   Option 1:
       flask run --debug

   Option 2 (if Flask doesn’t detect the app automatically):
       python app.py

   Once running, open your browser and go to:
       http://127.0.0.1:5000



 ###                   PROJECT STRUCTURE

Secure-Login-Simulation/
│
├── static/             → Static files (CSS, images)
├── templates/          → HTML templates (login, signup, dashboard)
├── instance/           → Contains the SQLite database
│   └── database.db
├── app.py              → Main Flask app file
├── create_db.py        → Script to initialize the database
├── requirements.txt    → Python dependencies
└── README.txt          → Project info (this file)



 ####                OPTIONAL: DEPLOY ON VERCEL


To deploy on Vercel, create a file named vercel.json
in your project root with the following content:

{
  "builds": [{ "src": "app.py", "use": "@vercel/python" }],
  "routes": [{ "src": "/(.*)", "dest": "app.py" }]
}

Then push your code to GitHub and import the repository
into your Vercel dashboard.


 ###                       REQUIREMENTS

- Python 3.8 or higher
- Flask
- Flask-SQLAlchemy
- Passlib
- Flask-WTF
- WTForms
- python-dotenv


 ###                          AUTHOR

Developed by: Zhen Yu / zhen-s22
GitHub: https://github.com/zhen-s22/Secure_login_simlulator
