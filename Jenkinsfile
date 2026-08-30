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
                    echo "Checking Employee API ServiceMonitor..."
                    kubectl get servicemonitor employee-api -n monitoring 

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
    stage('API Smoke Test') {
    steps {
        echo 'Running Employee API smoke test...'

        sh '''
            echo "=========================================="
            echo "Employee API Smoke Test"
            echo "=========================================="

            echo "Starting port-forward..."
            kubectl port-forward service/employee-api 8081:8080 > /tmp/employee-api-port-forward.log 2>&1 &

            PF_PID=$!

            # Give port-forward time to establish
            sleep 5

            echo "Testing Actuator Health endpoint..."

            curl --fail --silent --show-error \
                 http://127.0.0.1:8081/actuator/health

            echo ""
            echo "=========================================="
            echo "API Smoke Test PASSED"
            echo "Employee API is responding successfully."
            echo "=========================================="

            kill $PF_PID || true
        '''
    }
}
    }
}
