
copy_hooks:
	@ln -s confs/pre-commit .git/hooks/pre-commit
	@echo "+ Installed pre-commit hook"
