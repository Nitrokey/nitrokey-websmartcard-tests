all: CI

.PHONY: pipenv setup

setup: pipenv

pipenv: Pipfile.lock

Pipfile.lock:
	pipenv install

.PHONY: CI
CI: pipenv
	# Assuming UDP simulation is running
	pipenv run pytest test_comm.py -svx

.PHONY: hardware
hardware: U2F

.PHONY: FIDO2
FIDO2:
	env REAL_HARDWARE=1 TRANSPORT=FIDO2 pipenv run pytest --hardware test_comm.py

.PHONY: U2F
U2F:
	env REAL_HARDWARE=1 TRANSPORT=U2F pipenv run pytest --hardware test_comm.py


.PHONY: clean clean-full
clean:
	-rm -v *.bin *.log

clean-full: clean
	pipenv uninstall --all
	-rm Pipfile.lock
