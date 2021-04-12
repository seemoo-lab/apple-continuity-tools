PYTHON := python
VENV := venv

default: install

testvenv:
ifeq ($(VIRTUAL_ENV), )
	@echo "Virtual Python environment is not activated. Install and activate via:"
	@echo "make venv"
	@echo "source $(VENV)/bin/activate"
	@exit 1
endif

autoformat: install
	black .
	isort **/*.py
	npx prettier --write .

install: requirements.txt package-lock.json
	make testvenv
	$(PYTHON) -m pip install -r requirements.txt
	npm install

requirements.txt: requirements.in
	make testvenv
	$(PYTHON) -m pip install pip-tools
	$(PYTHON) -m piptools compile requirements.in

$(VENV):
	python3 -m venv $@

clean:
	rm -R $(VENV)

.PHONY: testvenv autoformat install clean
