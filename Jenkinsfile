import groovy.json.JsonOutput


timestamps {
  node('parallelizable') {
    stage('checkout') {
      scmInfo = checkout scm
      println("${scmInfo}")
      env.GIT_BRANCH = scmInfo.GIT_BRANCH
      env.GIT_COMMIT = scmInfo.GIT_COMMIT
    }

    stage('Build') {
      withCredentials([
        usernamePassword(credentialsId: '063fc85b-62a6-4181-9d72-873b43488411', usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY'),
        string(credentialsId: 'a791118f-a1ea-46cd-b876-56da1b9bc71c',variable: 'NEXUS_PASSWORD')
        ]) {
        sh '''\
        |cd $WORKSPACE
        |export GIT_BRANCH=${GIT_BRANCH}
        |export GIT_COMMIT=${GIT_COMMIT}
        |./ci/build_docker.sh
        |cp dist/**/*.txt dist/repaired_wheels/
        |cp dist/*.tar.gz dist/repaired_wheels/
        |aws s3 cp --only-show-errors ./dist/repaired_wheels/ s3://sfc-jenkins/repository/python_connector/linux/${GIT_BRANCH}/${GIT_COMMIT}/ --recursive --include '*'
        |echo ${GIT_COMMIT} > latest_commit
        |aws s3 cp --only-show-errors latest_commit s3://sfc-jenkins/repository/python_connector/linux/${GIT_BRANCH}/
        '''.stripMargin()
        }
      }
      params = [
        string(name: 'svn_revision', value: 'master'),
        string(name: 'branch', value: 'master'),
        string(name: 'client_git_commit', value: scmInfo.GIT_COMMIT),
        string(name: 'client_git_branch', value: scmInfo.GIT_BRANCH),
        string(name: 'parent_job', value: env.JOB_NAME),
        string(name: 'parent_build_number', value: env.BUILD_NUMBER)
      ]
      stage('Test') {
        parallel (
          'Test Python 36': { build job: 'RT-PyConnector36-PC',parameters: params},
          'Test Python 37': { build job: 'RT-PyConnector37-PC',parameters: params},
          'Test Python 38': { build job: 'RT-PyConnector38-PC',parameters: params},
          'Test Python 39': { build job: 'RT-PyConnector39-PC',parameters: params},
          'Test Python 310': { build job: 'RT-PyConnector310-PC',parameters: params},
          'Test Python Lambda 37': { build job: 'RT-PyConnector37-PC-Lambda',parameters: params}
          )
        }
      }
    }


pipeline {
  agent { label 'regular-memory-node' }
  options { timestamps() }
  environment {
    COMMIT_SHA_LONG = sh(returnStdout: true, script: "echo \$(git rev-parse " + "HEAD)").trim()
    SEMGREP_DEPLOYMENT_ID = 1
    INPUT_PUBLISHURL      = "https://semgrep.snowflake.com"

    // environment variables for semgrep_agent (for findings / analytics page)
    // remove .git at the end
    SEMGREP_REPO_URL = env.GIT_URL.replaceFirst(/^(.*).git$/,'$1')
    SEMGREP_BRANCH = "${CHANGE_BRANCH}"
    SEMGREP_JOB_URL = "${BUILD_URL}"
    // remove SCM URL + .git at the end
    SEMGREP_REPO_NAME = env.GIT_URL.replaceFirst(/^https:\/\/github.com\/(.*).git$/, '$1')

    SEMGREP_COMMIT = "${GIT_COMMIT}"
    SEMGREP_PR_ID = "${env.CHANGE_ID}"
    BASELINE_BRANCH = "${env.CHANGE_TARGET}"
  }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }
    stage('Semgrep_agent') {
      agent {
        docker {
          label 'parallelizable-c7'
          image 'nexus.int.snowflakecomputing.com:8087/returntocorp/semgrep-agent:v1'
          args '-u root'
        }
      }
      when {
        expression { env.CHANGE_ID && env.BRANCH_NAME.startsWith("PR-") }
      }
      steps{
        wrap([$class: 'MaskPasswordsBuildWrapper']) {
          withCredentials([
            [$class: 'UsernamePasswordMultiBinding', credentialsId:
                  'b4f59663-ae0a-4384-9fdc-c7f2fe1c4fca', usernameVariable:
                  'GIT_USERNAME', passwordVariable: 'GIT_PASSWORD'],
            string(credentialsId:'SEMGREP_APP_TOKEN', variable: 'SEMGREP_APP_TOKEN'),

          ]) {
            script {
              try {
                sh 'export SEMGREP_DIR=semgrep-scan-$(pwd | rev | cut -d \'/\' -f1 | rev) && mkdir -p ../$SEMGREP_DIR && cp -R . ../$SEMGREP_DIR  && cd ../$SEMGREP_DIR && git fetch https://$GIT_USERNAME:$GIT_PASSWORD@github.com/$SEMGREP_REPO_NAME.git $BASELINE_BRANCH:refs/remotes/origin/$BASELINE_BRANCH && python -m semgrep_agent --baseline-ref $(git merge-base origin/$BASELINE_BRANCH HEAD) --publish-token $SEMGREP_APP_TOKEN --publish-deployment $SEMGREP_DEPLOYMENT_ID && cd ../ && rm -r $SEMGREP_DIR'
                wgetUpdateGithub('success', 'semgrep', "${BUILD_URL}", '123')
              } catch (err) {
                wgetUpdateGithub('failure', 'semgrep', "${BUILD_URL}", '123')
              }
            }
          }
        }
      }
    }
  }
}

def wgetUpdateGithub(String state, String folder, String targetUrl, String seconds) {
    def ghURL = "https://api.github.com/repos/snowflakedb/snowflake-connector-python/statuses/$COMMIT_SHA_LONG"
    def data = JsonOutput.toJson([state: "${state}", context: "jenkins/${folder}",target_url: "${targetUrl}"])
    sh "wget ${ghURL} --spider -q --header='Authorization: token $GIT_PASSWORD' --post-data='${data}'"
}
