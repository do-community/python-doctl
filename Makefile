documentation:
	cd docs && make html
	rm -fr docs/_modules docs/_sources docs/_static
	mv docs/_build/html/* docs/
	git add -A 'docs'
	git commit -m 'docs'
