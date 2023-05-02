test-publish:
	-rm -r dist
	-rm -r build
	python3 -m build
	python3 -m twine upload --repository testpypi dist/*

test-upload:
	python3 -m twine upload --repository testpypi dist/*