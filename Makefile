all: CI

.PHONY: setup

setup:
	pipenv install

.PHONY: CI
CI:
	# Assuming UDP simulation is running
	pipenv run pytest test_comm.py -sv --template=html1/index.html --report=report-udp_simulation.html

.PHONY: hardware
hardware: U2F

.PHONY: FIDO2
FIDO2:
	env REAL_HARDWARE=1 TRANSPORT=FIDO2 pipenv run pytest --hardware test_comm.py --template=html1/index.html --report=report-fido2.html -v


.PHONY: U2F
U2F:
	env REAL_HARDWARE=1 TRANSPORT=U2F pipenv run pytest --hardware test_comm.py --template=html1/index.html --report=report-u2f.html

.PHONY: clean clean-full
clean:
	-rm -v *.bin *.log

clean-full: clean
	pipenv uninstall --all
	-rm Pipfile.lock
