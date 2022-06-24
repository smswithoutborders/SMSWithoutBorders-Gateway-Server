
copy_hooks:
	@ln -s -f ../../confs/pre-commit .git/hooks/pre-commit
	@echo "+ Installed pre-commit hook"
	@touch test/userid
	@echo "+ Created test/userid file"
