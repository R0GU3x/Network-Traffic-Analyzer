# Xylem - Network Analyzer

## Introduction
Xylem is a powerful network analyzer designed to enhance cybersecurity by using advanced machine learning algorithms to detect and respond to zero-day vulnerabilities. Developed during a 36-hour hackathon at Parul University, Gujarat, organized by Onsite, Xylem provides real-time insights into network traffic and potential threats.

## Features
- **User-friendly Dashboard:** A comprehensive dashboard with 13 distinct panels displaying real-time traffic flow information.
- **Machine Learning:** Advanced algorithms to detect malicious packets within network traffic.
- **Severity Ranking:** Helps administrators prioritize which attacks to address first.
- **Geographical Map:** Traces the threat actor's location.
- **Detailed Logging:** Provides thorough threat inspection logs.

## Technologies Used
- **Back-end:** Python
- **Database:** MySQL
- **Front-end:** Grafana
- **Machine Learning:** Integrated algorithms for threat detection

## Installation
1. **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/Xylem.git
    ```
2. **Navigate to the project directory:**
    ```bash
    cd Xylem
    ```
3. **Set up a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
4. **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
5. **Set up the MySQL database:**
    - Create a new database.
    - Update the database configuration in the `config.py` file with your database details.

6. **Run the application:**
    ```bash
    python app.py
    ```

## Usage
1. **Access the Dashboard:**
    - Navigate to `http://localhost:3000` to access the Grafana dashboard.
    - Login with the default credentials (admin/admin) and set up your dashboard.

2. **Monitoring Network Traffic:**
    - The dashboard will display real-time traffic flow and detected threats.

## Contributing
We welcome contributions to enhance Xylem! To contribute:
1. Fork the repository.
2. Create a new branch: `git checkout -b feature-name`
3. Make your changes and commit them: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature-name`
5. Open a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contact
For any questions or suggestions, feel free to reach out:
- **Email:** your.email@example.com
- **LinkedIn:** [Your LinkedIn Profile](https://www.linkedin.com/in/yourprofile)

## Acknowledgements
Special thanks to my teammates Vaibhav, Mansvi, and Riya, and our mentor Sandip Jha for their support and guidance during the development of Xylem.

## Links
- **YouTube:** [Project Demo](https://youtube.com/link)
- **GitHub:** [Repository](https://github.com/yourusername/Xylem)
