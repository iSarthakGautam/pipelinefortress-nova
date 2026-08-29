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
                sh './mvnw clean package'

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

        stage('Deploy to Kubernetes') {
            steps {
                echo 'Deploying Employee API to Kubernetes using Ansible...'

                sh '''
                    ansible-playbook \
                      -i ansible/inventory.ini \
                      ansible/deploy.yml
                '''
            }
        }

        stage('Deployment Verification') {
            steps {
                echo 'Verifying Employee API deployment...'

                sh '''
                    echo "=========================================="
                    echo "Deployment Verification"
                    echo "=========================================="

                    echo "Checking Kubernetes deployment..."
                    kubectl get deployment employee-api

                    echo ""
                    echo "Checking Employee API pods..."
                    kubectl get pods -l app=employee-api

                    echo ""
                    echo "Checking Employee API service..."
                    kubectl get service employee-api

                    echo ""
                    echo "Checking rollout status..."
                    kubectl rollout status deployment/employee-api --timeout=120s

                    echo ""
                    echo "=========================================="
                    echo "Deployment Verification PASSED"
                    echo "=========================================="
                '''
            }
        }
    }
}
