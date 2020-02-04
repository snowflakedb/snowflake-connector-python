// Liberally swiped from https://github.com/actions/github/blob/master/entrypoint.js
//

const {Toolkit} = require('actions-toolkit')

const tools = new Toolkit()

if (process.env.DEBUG === 'true') debug()

doTitle(tools.arguments)
  .then(() => {
    tools.exit.success('action successful')
  })
  .catch(err => {
    tools.log.fatal(err)
    tools.exit.failure('action failed')
  })

async function doTitle() {
  filterAction(tools.arguments.action)
  const jira = process.env.INPUT_JIRA
  const newtitle = `${ jira }: ${ tools.context.payload.issue.title }`
  tools.log.info('title', newtitle)
  return checkStatus(
    await tools.github.issues.update({owner: tools.context.payload.repository.owner.login,
                                      repo: tools.context.payload.repository.name,
                                      issue_number: tools.context.payload.issue.number,
                                      title: newtitle})
  )
}

function checkStatus(result) {
  if (result.status >= 200 && result.status < 300) {
    return result
  }

  tools.exit.failure(`Received status ${result.status} from API.`)
}

function filterAction(action) {
  if (!action) return

  if (tools.context.payload.action !== action) {
    tools.log.note(
      `Action "${
        tools.context.payload.action
      } does not match "${action}" from arguments.`
    )

    tools.exit.neutral()
  }
}

function debug() {
  tools.log.debug('Action', tools.context.action)
  tools.log.debug('Actor', tools.context.actor)
  tools.log.debug('Arguments', tools.arguments)
  tools.log.debug('Event', tools.context.event)
  tools.log.debug('Payload', tools.context.payload)
  tools.log.debug('Ref', tools.context.ref)
  tools.log.debug('Sha', tools.context.sha)
  tools.log.debug('Workflow', tools.context.workflow)
  if (process.env.DEBUG_PAYLOAD === 'true')
    tools.log.debug('Payload', tools.context.payload)
}
