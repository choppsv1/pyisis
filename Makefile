PYLINT=pylint

PIP3=/home/chops/local/bin/pip3
PYLINT3=/home/chopps/local/bin/pylint3
PYTEST3=/home/chopps/local/bin/py.test
PYTHON3=/home/chopps/local/bin/python3

PIP=/home/chops/venv/bin/pip
PYLINT=/home/chopps/venv/bin/pylint
PYTEST=/home/chopps/venv/bin/py.test
PYTHON=python

TSFILE=.lint-timestamp

check:
	@echo Running lint on changes XRUT with PYLINT=$(PYLINT)
	@OK=YES; for f in $$(git status | awk '/^[ \t]+(modified|new file): +.*.py$$/{print $$2}'); do if [[ $$f -nt $(TSFILE) ]]; then echo "=== $$f"; if ! $(PYLINT) -r n --rcfile=pylintrc $$f; then OK=NO; fi; fi; done; if [[ $$OK = YES ]]; then touch $(TSFILE); fi

clean:
	find . -name '*.pyc' -exec rm {} +
	$(PYTHON) setup.py clean
	$(PYTHON3) setup.py clean
	rm -rf bulid

install:
	$(PIP) install -e .
	$(PIP3) install -e .

uninstall:
	$(PIP) uninstall -y pyisis
	$(PIP3) uninstall -y pyisis

lint2:
	@for f in $$(find pyisis -name '*.py'); do \
		echo "=== Linting $$f"; \
		$(PYLINT) -r n --rcfile=pylintrc $$f; \
	done

lint3:
	@for f in $$(find pyisis -name '*.py'); do \
		echo "=== Linting $$f"; \
		$(PYLINT3) -r n --rcfile=pylintrc $$f; \
	done

test:	lint2 test2 lint3 test3

test2:
	@echo "Running python v2 tests"
	$(PYTEST) -v --doctest-modules

test3:
	@echo "Running python v3 tests"
	$(PYTEST3) -v --doctest-modules

docker:
	docker build --network=host -t pyisis .
