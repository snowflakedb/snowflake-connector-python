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
        |cp dist/src/* dist/repaired_wheels/
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
          'Test Python Lambda 37': { build job: 'RT-PyConnector37-PC-Lambda',parameters: params}
          )
        }
      }
    }
