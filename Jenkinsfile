pipeline {
    // agent {
    //     // L'agent doit disposer de Docker, Python, Git, curl et Trivy.
    //     label 'docker'
    // }    
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds(abortPrevious: true)

        buildDiscarder(
            logRotator(
                numToKeepStr: '20',
                artifactNumToKeepStr: '10'
            )
        )
    }

    parameters {
        string(
            name: 'REPORT_EMAIL',
            defaultValue: 'tanguy.vienot.pers@gmail.com',
            description: 'Adresse qui recevra le rapport PDF'
        )
    }

    environment {
        IMAGE_REF = 'app:latest'

        REPORT_DIR = 'tools/generate_report'

        SONAR_HOST_URL = 'https://sonarcloud.io'
        SONAR_PROJECT_KEY = 'Advil400mg_devsecops'

        APP_CHANGED = 'true'
        PYTHONUNBUFFERED = '1'

    }


    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Docker image') {
            steps {
                sh '''
                    set -eu

                    docker build \
                        --tag "$IMAGE_REF" \
                        .
                '''
            }
        }

        stage('Scan Docker image with Trivy') {
            steps {
                sh '''
                    set -eu

                    mkdir -p "$REPORT_DIR"

                    trivy image \
                        --exit-code 0 \
                        --severity MEDIUM,HIGH,CRITICAL \
                        --format json \
                        --output "$REPORT_DIR/trivy-report.json" \
                        "$IMAGE_REF"

                    test -s "$REPORT_DIR/trivy-report.json"
                '''
            }
        }

        stage('Install Python dependencies') {
            steps {
                sh '''
                    set -eu

                    python3 -m venv .venv

                    . .venv/bin/activate

                    python -m pip install --upgrade pip
                    pip install --requirement app/requirements.txt
                '''
            }
        }

        stage('Detect changes in app') {
            steps {
                script {
                    /*
                     * Jenkins fournit généralement ces commits après le
                     * checkout effectué par le plugin Git.
                     */
                    def baseCommit =
                        env.GIT_PREVIOUS_SUCCESSFUL_COMMIT ?:
                        env.GIT_PREVIOUS_COMMIT

                    if (!baseCommit) {
                        // Premier build : on exécute SonarCloud.
                        env.APP_CHANGED = 'true'
                    } else {
                        int diffStatus = sh(
                            script: """
                                git diff --quiet \
                                    ${baseCommit} \
                                    HEAD \
                                    -- app/
                            """,
                            returnStatus: true
                        )

                        if (diffStatus > 1) {
                            error(
                                "Impossible de comparer HEAD avec ${baseCommit}"
                            )
                        }

                        env.APP_CHANGED =
                            diffStatus == 1 ? 'true' : 'false'
                    }

                    echo "Changes detected in app/: ${env.APP_CHANGED}"
                }
            }
        }

        stage('SonarCloud Scan') {
            when {
                expression {
                    env.APP_CHANGED == 'true'
                }
            }

            steps {
                script {
                    /*
                     * "SonarScanner" est le nom configuré dans :
                     * Manage Jenkins -> Tools.
                     */
                    def scannerHome = tool 'SonarScanner'

                    /*
                     * "SonarCloud" est le nom configuré dans :
                     * Manage Jenkins -> System -> SonarQube installations.
                     */
                    withSonarQubeEnv('SonarCloud') {
                        withEnv(["SCANNER_HOME=${scannerHome}"]) {
                            sh '''
                                set -eu

                                "$SCANNER_HOME/bin/sonar-scanner"
                            '''
                        }
                    }
                }
            }
        }

        stage('Wait for SonarCloud analysis') {
            when {
                expression {
                    env.APP_CHANGED == 'true'
                }
            }

            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    script {
                        def qualityGate = waitForQualityGate(
                            abortPipeline: false
                        )

                        echo(
                            "SonarCloud Quality Gate: " +
                            "${qualityGate.status}"
                        )
                    }
                }
            }
        }

        stage('Get SonarCloud issues') {
            steps {
                /*
                 * Secret Text credential Jenkins :
                 * ID = sonar-token
                 */
                withCredentials([
                    string(
                        credentialsId: 'sonar-token',
                        variable: 'SONAR_TOKEN'
                    )
                ]) {
                    sh '''
                        set -eu

                        mkdir -p "$REPORT_DIR"

                        curl \
                            --fail \
                            --silent \
                            --show-error \
                            --user "$SONAR_TOKEN:" \
                            --get \
                            --data-urlencode \
                                "componentKeys=$SONAR_PROJECT_KEY" \
                            --output \
                                "$REPORT_DIR/sonar-report.json" \
                            "$SONAR_HOST_URL/api/issues/search"
                    '''
                }
            }
        }

        stage('Generate PDF report') {
            steps {
                sh '''
                    set -eu

                    .venv/bin/python \
                        "$REPORT_DIR/generate.py"

                    test -s "$REPORT_DIR/scans-report.pdf"
                '''
            }
        }

        stage('Archive PDF report') {
            steps {
                archiveArtifacts(
                    artifacts:
                        'tools/generate_report/scans-report.pdf',
                    fingerprint: true
                )
            }
        }

        stage('Send email') {
            steps {
                emailext(
                    to: params.REPORT_EMAIL,

                    subject:
                        "PIPELINE PDF Report - " +
                        "${env.JOB_NAME} #${env.BUILD_NUMBER}",

                    body:
                        """The DevSecOps pipeline completed successfully.

The SonarCloud and Trivy PDF report is attached.

Jenkins job: ${env.JOB_NAME}
Build number: ${env.BUILD_NUMBER}
Build URL: ${env.BUILD_URL}
""",

                    mimeType: 'text/plain',

                    attachmentsPattern:
                        'tools/generate_report/scans-report.pdf'
                )
            }
        }
    }

    post {
        success {
            echo 'DevSecOps pipeline completed successfully.'
        }

        failure {
            echo 'DevSecOps pipeline failed.'
        }

        always {
            sh '''
                docker image rm "$IMAGE_REF" \
                    >/dev/null 2>&1 || true
            '''

            deleteDir()
        }
    }
}