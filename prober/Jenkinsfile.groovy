pipeline {
    agent { label 'regular-memory-node' }

    options {
        ansiColor('xterm')
        timestamps()
    }

    environment {
        VAULT_CREDENTIALS = credentials('vault-jenkins')
        COMMIT_SHA_SHORT = '1234567890' // sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
        IMAGE_NAME = 'drivers/python-driver-prober'
        TEAM_NAME = 'Snow Drivers'
        TEAM_JIRA_DL = 'triage-snow-drivers-warsaw-dl'
        TEAM_JIRA_AREA = 'Developer Platform'
        TEAM_JIRA_COMPONENT = 'Python Driver'
    }

    stages {
        stage('Build Image') {
            steps {
                dir('./PythonConnector/prober') {
                    sh """
                    ls -l
                    docker build \
                    -t ${IMAGE_NAME}:${COMMIT_SHA_SHORT} -f ./Dockerfile_min .
                    """
                }
            }
        }

        stage('Checkout Jenkins Push Scripts') {
            steps {
                dir('k8sc-jenkins_scripts') {
                    git branch: 'master',
                    credentialsId: 'jenkins-snowflake-github-app-3',
                    url: 'https://github.com/snowflakedb/k8sc-jenkins_scripts.git'
                }
            }
        }

        stage('Push Image') {
            steps {
                sh """
                ./k8sc-jenkins_scripts/jenkins_push.sh \
                -r "${VAULT_CREDENTIALS_USR}" \
                -s "${VAULT_CREDENTIALS_PSW}" \
                -i "${IMAGE_NAME}" \
                -v "${COMMIT_SHA_SHORT}" \
                -n "${TEAM_JIRA_DL}" \
                -a "${TEAM_JIRA_AREA}" \
                -C "${TEAM_JIRA_COMPONENT}"
                """
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
