CDR: NeuroForensic Platform

A locally hosted Call Detail Record (CDR) forensic analysis platform developed for telecom investigation, communication-pattern analysis, relationship mapping, behavioural analysis, and geolocation intelligence.

The platform automates the ingestion and analysis of telecom datasets that would otherwise require manual examination of large spreadsheets. It provides investigators with structured forensic insights through an interactive cyber-forensic web interface.

Project Overview

CDR: NeuroForensic is a web-based forensic intelligence application built using Python and Flask with an HTML5 and JavaScript frontend.

The application accepts CSV-based Call Detail Records and processes them to identify communication patterns, frequently contacted numbers, activity trends, relationship networks, behavioural anomalies, and approximate device location.

The system operates locally, supporting a controlled environment for forensic investigation and data confidentiality.

Features

1. CDR CSV Upload and Decoding

- Upload telecom datasets in CSV format.
- Automatically parse and process communication records.

2. Records Analysis

- View raw CDR entries.
- Display called numbers, date/time, duration, and communication type.
- Records are presented in chronological and paginated form.

3. Top Contact Analysis

- Rank contacts according to interaction frequency.
- Identify frequently contacted numbers.
- Determine dominant communication associates.

4. Hourly Communication Pattern

- Analyse communication activity by hour.
- Identify peak communication periods.
- Analyse behavioural timing patterns.

5. Relationship Mapping

- Generate a graphical representation of the target's communication network.
- Display the target and associated contacts as interconnected nodes.
- Understand the communication ecosystem of the subject.

6. Behavioural Anomaly Detection

- Analyse communication behaviour for irregular patterns.
- Identify unusual spikes and communication bursts.
- Detect deviations from expected behavioural patterns.

7. Geolocation Intelligence

- Estimate the approximate location of the target device using telecom tower information.
- Provide estimated latitude and longitude coordinates.

8. Local Forensic Environment

- Runs locally to support controlled investigation workflows.
- Helps maintain confidentiality of forensic data.

Technology Stack

Component| Technology
Backend| Python
Web Framework| Flask
Frontend| HTML5, JavaScript
Input Format| CSV
Data Processing| CSV parsing and automated record decoding
Visualisation| Dynamic graphical visualisation
Network Analysis| Relationship/network graph rendering
Deployment| Localhost

The technical architecture consists of a Python/Flask backend, HTML5/JavaScript frontend, CSV processing, graphical visualisation, relationship mapping, and coordinate estimation.

Application Modules

CDR: NeuroForensic
│
├── Upload & Decode
│
├── Records
│   └── Raw CDR Records
│
├── Top Contacts
│   └── Contact Frequency Analysis
│
├── Hourly Pattern
│   └── Communication Timing Analysis
│
├── Relationship Mapping
│   └── Communication Network
│
├── Behavioural Anomaly Detection
│   └── Pattern Analysis
│
└── Geolocation Intelligence
    └── Approximate Location Estimation

Forensic Applications

CDR analysis can assist forensic investigators in:

- Reconstructing communication timelines
- Identifying frequently contacted individuals
- Understanding communication relationships
- Analysing communication frequency
- Identifying peak communication periods
- Detecting unusual communication behaviour
- Understanding the communication network of a target
- Estimating approximate device location

These capabilities demonstrate how CDR analysis can support communication and behavioural analysis during forensic investigations.

Sample Case

The technical report demonstrates the platform using a sample CDR dataset containing 73 communication records.

Sample Findings

Parameter| Result
Total Records Analysed| 73
Target Number|Sample/Anonymized
Associated Contacts| Approximately 35
Highest-Frequency Contact| Anonymized
Highest Interaction Count| 15 communications
Peak Communication Hour| 20:00
Peak Activity| 14 events
Behavioural Anomalies| No significant anomalies detected
Estimated Latitude| 28.6698
Estimated Longitude| 77.2416

The report identified Anonymized  as the most frequently contacted number, with 15 communications, and 20:00 as the peak communication hour with 14 events.

Installation and Setup

1. Clone the Repository

git clone <YOUR-GITHUB-REPOSITORY-URL>
cd <PROJECT-FOLDER>

2. Create a Virtual Environment

python -m venv venv

3. Activate the Virtual Environment

For Windows:

venv\Scripts\activate

4. Install Dependencies

pip install -r requirements.txt

5. Run the Application

python app.py

The application is designed to run in a local environment. The report specifies the deployment address as:

127.0.0.1:8001

Suggested Project Structure

CDR-NeuroForensic/
│
├── app.py
├── requirements.txt
├── README.md
│
├── templates/
│   ├── index.html
│   ├── records.html
│   ├── contacts.html
│   ├── hourly.html
│   ├── relationship.html
│   ├── anomaly.html
│   └── geolocation.html
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── dataset/
│   └── sample_cdr.csv
│
└── screenshots/
    └── application-screenshots/

Note: Adjust the structure above according to the actual files and folders in your repository.

Limitations

Current Limitation| Future Enhancement
Limited geolocation precision| Integration with live telecom tower APIs
Local-only deployment| Cloud forensic deployment
Single-dataset analysis| Multi-subject correlation analysis
No automated report export| PDF/DOCX forensic report generation
Basic anomaly detection| AI-based behavioural intelligence

These limitations and corresponding future enhancements are identified in the technical report.

Future Scope

Future development of the platform can include:

- Advanced AI-based behavioural analysis
- Improved real-time geolocation intelligence
- Cloud-based forensic deployment
- Multi-subject CDR correlation
- Automated forensic report generation
- Advanced anomaly and suspicious-pattern detection
- Enhanced investigative visualisations

The report identifies advanced anomaly detection, real-time geolocation, and automated intelligence reporting as important areas for future development.

Privacy and Ethical Use

CDR data may contain sensitive communication information. This project should be used only with legally obtained, authorised, or synthetic datasets and in accordance with applicable privacy, forensic, and telecommunications laws.

Do not upload real individuals' CDR data to a public GitHub repository.

Use sample or anonymised datasets for demonstrations and testing.

Project Information

Project: CDR: NeuroForensic Platform
Domain: Mobile and Network Forensics
Backend: Python / Flask
Frontend: HTML5 / JavaScript
Deployment: Localhost
Input: CSV-based CDR Dataset
