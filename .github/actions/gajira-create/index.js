const fs = require('fs')
const core = require('@actions/core')

const Action = require('./action')

// eslint-disable-next-line import/no-dynamic-require
const githubEvent = require(process.env.GITHUB_EVENT_PATH)
const config = {
  baseUrl: process.env.JIRA_BASE_URL,
  token: process.env.JIRA_API_TOKEN,
  email: process.env.JIRA_USER_EMAIL
}

async function exec () {
  try {
    const args = {
        project: process.env.INPUT_PROJECT,
        issuetype: process.env.INPUT_TYPE,
        summary: process.env.INPUT_SUMMARY,
        description: process.env.INPUT_DESCRIPTION,
        area: process.env.INPUT_AREA,
        assignee: process.env.INPUT_ASSIGNEE
    }

    console.log("ARGS")
    console.log(JSON.stringify(args, null, 4))

    const result = await new Action({
      githubEvent,
      argv: args,
      config,
    }).execute()

    if (result) {
      // result.issue is the issue key
      console.log(`Created issue: ${result.issue}`)

      // Expose created issue's key as an output
      core.setOutput("issue", result.issue)

      return true
    }

    console.log('Failed to create issue.')
    process.exit(78)
  } catch (error) {
    console.error(error)
    process.exit(1)
  }
}

exec()
