import groovy.json.JsonOutput


timestamps {
  node('parallelizable-c7') {
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
        string(name: 'svn_revision', value: 'main'),
        string(name: 'branch', value: 'main'),
        string(name: 'client_git_commit', value: scmInfo.GIT_COMMIT),
        string(name: 'client_git_branch', value: scmInfo.GIT_BRANCH),
        string(name: 'parent_job', value: env.JOB_NAME),
        string(name: 'parent_build_number', value: env.BUILD_NUMBER)
      ]
      stage('Test') {
        parallel (
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

    // environment variables for semgrep_agent (for findings / analytics page)
    // remove .git at the end
    // remove SCM URL + .git at the end

    BASELINE_BRANCH = "${env.CHANGE_TARGET}"
  }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }
  }
}

def wgetUpdateGithub(String state, String folder, String targetUrl, String seconds) {
    def ghURL = "https://api.github.com/repos/snowflakedb/snowflake-connector-python/statuses/$COMMIT_SHA_LONG"
    def data = JsonOutput.toJson([state: "${state}", context: "jenkins/${folder}",target_url: "${targetUrl}"])
    sh "wget ${ghURL} --spider -q --header='Authorization: token $GIT_PASSWORD' --post-data='${data}'"
}
