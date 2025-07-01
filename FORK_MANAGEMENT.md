# Fork Management Guidelines

This repository is a fork of [snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python) with async implementation.

## Branch Structure

### `main` Branch - PROTECTED 🔒
- **Purpose**: Clean copy of upstream repository
- **Protection**: Branch protection enabled - requires PR approval
- **Usage**: ONLY for syncing upstream changes
- **Never**: Direct pushes, feature development, or async code

### `aio` Branch - Development
- **Purpose**: Async implementation and all development
- **Usage**: Feature development, bug fixes, publishing
- **Contains**: All async code in `src/snowflake/connector/aio/`

## Syncing with Upstream

To sync upstream changes into the fork:

```bash
# Sync main branch (the only time main should be modified)
git checkout main
git fetch upstream
git merge upstream/main
git push origin main

# Merge upstream changes into aio branch
git checkout aio  
git merge main
# Resolve conflicts if any
git push origin aio
```

## Development Workflow

1. **All development happens on `aio` branch**
2. **Never modify `main` branch directly**
3. **Publish from `aio` branch** (setup.cfg is configured for `snowflake-connector-python-async`)

## Branch Protection Details

The `main` branch is protected with:
- ✅ Requires pull request reviews (1 approval)
- ✅ Dismisses stale reviews
- ✅ Prevents force pushes
- ✅ Prevents deletions
- ✅ Prevents direct pushes

This ensures `main` stays clean and only receives upstream changes.