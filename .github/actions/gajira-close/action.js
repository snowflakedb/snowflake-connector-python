const _ = require('lodash')
const Jira = require('./common/net/Jira')

module.exports = class {
    constructor({githubEvent, argv, config}) {
        this.Jira = new Jira({
            baseUrl: config.baseUrl,
            token: config.token,
            email: config.email,
        })

        this.config = config
        this.argv = argv
        this.githubEvent = githubEvent
    }

    async execute() {
        const {argv} = this

        const issueId = argv.issue

        await this.Jira.transitionIssue(issueId, {
            update: {
                comment: [
                    {add: {body: "Closed on GitHub"}}
                ]
            },
            fields: {
                customfield_12860: {id: "11506"},
                customfield_13132: {id: "12467"},
                customfield_10800: {id: "-1"},
                customfield_12500: {id: "11302"},
                customfield_12400: {id: "-1"},
                resolution: {name: "Done"}
            },
            transition: {id: "71"}
        })

        const transitionedIssue = await this.Jira.getIssue(issueId)

        console.log(`Changed ${issueId} status to : ${_.get(transitionedIssue, 'fields.status.name')} .`)
        console.log(`Link to issue: ${this.config.baseUrl}/browse/${issueId}`)

        return {}
    }
}
