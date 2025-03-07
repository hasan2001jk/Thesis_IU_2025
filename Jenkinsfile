pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building...'
                // Your build commands here
            }
        }
        stage('Test') {
            steps {
                echo 'Testing...'
                sleep (1000)
                // Your test commands here
            }
        }
        stage('Secrets') {
            steps {
                echo """           "Starting build process...\n" +
                        "Cloning repository...\n" +
                        "Setting AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
                        "Setting AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
                        "Using API_KEY=1234567890abcdef1234567890abcdef\n" +
                        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n" +
                        "password=supersecretpassword123\n" +
                        "credit-card=4111111111111111\n" +  // From sensitive-fields-simple.yml
                        "social_security_number=123-45-6789\n" +  // From pii-stable.yml
                        "Using GitHub token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890\n" +
                        "Build completed successfully.\n";"""
            }
        }
    }
}
