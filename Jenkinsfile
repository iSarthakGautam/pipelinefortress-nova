```groovy
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
    }
}
```
