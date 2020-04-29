#!/bin/bash -e
#
# Writes to stdout the svn revision number for the current or specified directory.
#

# If caller specified a directory, change to it.
if [ "$1" ]; then
  cd "$1" || exit $?
fi

# in case of svn or git error, keep going
set +o pipefail

# Try to get revision number from Subversion.
svnrevision=$(svn info 2>/dev/null | grep "Last Changed Rev:" | awk "{ print \$4 }" || true)
if [ "$svnrevision" ]; then
  echo "$svnrevision"
  exit 0
fi

# Not svn. Is there a git repository associated with this directory?
if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = "true" ]; then

  # If properly set up, each downloaded upstream commit should be accompanied by a
  # line of git notes containing its svn revision number and branch path.
  #
  # This is what the user has to do to make these notes available:
  #     git config --add remote.origin.fetch '+refs/svn/map:refs/notes/commits'
  #     git pull
  #
  # We can find this by looking at the most recent commit from master that also
  # appears in the currently checked out branch.

  declare -a logwords=($(git show --quiet --pretty=format:%N $(git merge-base HEAD master) || true))
  svnrevision=${logwords[0]#r}
  if [ "$svnrevision" ]; then
    echo "$svnrevision"
    exit 0
  fi

  # Failed to find a SVN rev; use git ref hash instead
  # SNOW-132287
  git_root=$(git rev-parse --show-toplevel)
  cwd=$(pwd)
  if [[ $cwd == $git_root ]]; then
    # no path will pick up merge commits, which we want
    svnrevision=$(git log --pretty=format:%H -n 1)
  else
    svnrevision=$(git log --pretty=format:%H -n 1 .)
  fi
  if [ "$svnrevision" ]; then
    # Sometimes we want the date as an integer, this forces git to provide an integer with the committer date in YYYYMMDDHHMMSS
    if [[ x"$2" == "xFORCE_INT" ]]; then
        svnrevision=$(git log --date=format:'%Y%m%d%H%M%S' --pretty=format:%cd -n 1)
    fi
    echo "$svnrevision"
    exit 0
  fi

  echo "If you've cloned from a subgit repo, to enable svn revision tracking you should:" >&2
  echo "    git config --add remote.origin.fetch '+refs/svn/map:refs/notes/commits'" >&2
  echo "    git pull" >&2

fi

# Couldn't find version info. Maybe this directory is not under SCM?
echo "Error ($0): Unable to get svn info for directory `pwd`" >&2
exit 99
