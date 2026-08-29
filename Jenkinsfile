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
                sh './mvnw clean test'
            }
        }

        stage('SAST - Semgrep') {
            steps {
                sh '''
                    docker run --rm \
                      -v jenkins_home:/src \
                      semgrep/semgrep \
                      semgrep --config=p/java --error /src/workspace/employee-api-pipeline
                '''
            }
        }

        stage('Docker Build') {
            steps {
                sh 'docker build -t employee-api:jenkins .'
            }
        }

        stage('Container Security - Trivy') {
            steps {
                sh '''
                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      aquasec/trivy:latest \
                      image \
                      --severity HIGH,CRITICAL \
                      --exit-code 1 \
                      employee-api:jenkins
                '''
            }
        }
    }
}
