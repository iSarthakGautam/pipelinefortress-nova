pipeline {
    agent any

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build and Test') {
            steps {
                // Build the application, run tests, and create the JAR
                sh './mvnw clean package'

                // Verify that the JAR was created for the Docker build
                sh 'ls -lh target/employee-api-*.jar'
            }
        }

        stage('SAST - Semgrep') {
            steps {
                sh '''
                    echo "=========================================="
                    echo "Running Semgrep SAST scan"
                    echo "=========================================="

                    docker run --rm \
                      -v jenkins_home:/src \
                      semgrep/semgrep \
                      semgrep --config=p/java --error /src/workspace/employee-api-pipeline

                    echo "Semgrep SAST scan completed successfully."
                '''
            }
        }

        stage('Docker Build') {
            steps {
                echo 'Building Employee API Docker image...'

                sh '''
                    docker build -t employee-api:jenkins .
                    docker images | grep employee-api
                '''
            }
        }

        stage('Container Security - Trivy') {
            steps {
                sh '''
                    echo "=========================================="
                    echo "Trivy Container Security Scan"
                    echo "=========================================="
                    echo "NOTE: HIGH/CRITICAL vulnerabilities will"
                    echo "be reported but will NOT block/fail the build."
                    echo "but in production like env, as these findings should be"
                    echo "reviewed and remediated so we can failed the build as well using the exit code"
                    echo "=========================================="

                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      aquasec/trivy:latest \
                      image \
                      --severity HIGH,CRITICAL \
                      employee-api:jenkins

                    echo "=========================================="
                    echo "Trivy scan completed."
                    echo "Pipeline continues for demonstration."
                    echo "=========================================="
                '''
            }
        }
    }
}
