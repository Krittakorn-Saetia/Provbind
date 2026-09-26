def pytest_configure(config):
    config.addinivalue_line("markers", "integration: needs Docker and the local registry at localhost:5001")
