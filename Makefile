documentation:
	sphinx-build docs docs/build
	mv docs/build/* docs/
	mv docs/build/.* docs/