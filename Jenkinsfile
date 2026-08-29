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
                      -v "$WORKSPACE:/src" \
                      semgrep/semgrep \
                      semgrep --config=p/java --error
                '''
            }
        }

        stage('Docker Build') {
            steps {
                sh 'docker build -t employee-api:jenkins .'
            }
        }
    }
}
