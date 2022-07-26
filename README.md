# Nitrokey Webcrypt Tests



## Setting up

### Tests
1. Python 3.10 with `pipenv`

To install Python dependencies for this project only it suffices to call:
```bash
pipenv install
```

### Building simulation
Please refer to the main project readme for details:
- https://github.com/Nitrokey/nitrokey-webcrypt-rust#running-udp-simulation

## Running tests

### Simulation
It is possible to test the implementation using simulation without the actual hardware. The process and tests communicate via UDP.


#### Running
Please refer to the main project readme for details regarding how to run the UDP simulation:
- https://github.com/Nitrokey/nitrokey-webcrypt-rust#running-udp-simulation


Running actual tests:
```bash
pipenv run pytest test_comm.py
```

Same, but write live logs to output:
```bash
pipenv run pytest test_comm.py  -svx --log-cli-level=DEBUG
```

### Hardware

Similarly to the simulation case, but with `--hardware` switch and additional environment variables:
- `env REAL_HARDWARE=1 TRANSPORT=FIDO2` for FIDO2 transport
- `env REAL_HARDWARE=1 TRANSPORT=U2F` for U2F transport

E.g. for the U2F transport:
```bash
env REAL_HARDWARE=1 TRANSPORT=U2F pipenv run pytest --hardware test_comm.py
```

## CI
For the CI use a Makefile is prepared, which automatically setups and runs both the simulation and tests.
The UDP simulation has to be executed before that.
Execution:
```bash
make
```
