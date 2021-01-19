# Vendored actions

## Purpose
These modified GitHub actions have been included here because publicly
existing versions of these actions are not quite good enough for us. A good
example of this is our custom Jira fields, so we include a lot of Jira
related actions.

## Updating actions
First please see [the documentation](https://docs.github.com/en/free-pro-team@latest/actions/creating-actions)
for what different files do in a GitHub action.

*Note: The following steps were written for CentOS 7.*

1. Install ``nvm`` with ``sudo yum install nvm``.
2. Install NodeJS 12 with ``nvm install v12``.
3. Activate NodeJS 12 with ``nvm use v12``.
4. Navigate to one of the directories from in this directory.
5. Install the project with ``npm install``.
6. Modify the source code as you see fit.
7. Rebuild the dist folder with ``npm run-script build``.
8. Check in new files.
