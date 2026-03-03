.PHONY: install test lint clean docker-build docker-run help

help:
	@echo "EntropyGuard Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install       - Install dependencies"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linters"
	@echo "  clean         - Clean build artifacts"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v

lint:
	flake8 entropyguard/ --max-line-length=100
	mypy entropyguard/ --ignore-missing-imports

clean:
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docker-build:
	docker build -t entropyguard .

docker-run:
	docker run -v $$(pwd)/disks:/data entropyguard scan /data/disk.dd

format:
	black entropyguard/ tests/

setup-dev:
	pip install -r requirements.txt
	pre-commit install

train-sample:
	python scripts/generate_synthetic.py
	entropyguard train test_disk.dd --output models/
