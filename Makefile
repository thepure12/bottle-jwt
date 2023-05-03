test-publish:
	-rm -r dist
	-rm -r build
	python3 -m build
	python3 -m twine upload --repository testpypi dist/*

test-upload:
	python3 -m twine upload --repository testpypi dist/*

publish:
	-rm -r dist
	-rm -r build
	python3 -m build
	python3 -m twine upload --repository pypi dist/*

upload:
	python3 -m twine upload --repository pypi dist/*