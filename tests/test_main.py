import pytest
import subprocess
import shlex
import glob
import os
import json
from pathlib import Path


TEST_DIR = Path(__file__).resolve().parent


def run_command(command):
    """Helper to run a shell command and return its output, with error handling."""
    try:
        result = subprocess.run(
            shlex.split(command),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command '{command}' failed with error: {e.stderr}")


def detect_container_engine():
    """Detects whether Docker or Podman is available."""
    try:
        run_command("docker --version")
        return "docker"
    except FileNotFoundError:
        try:
            run_command("podman --version")
            return "podman"
        except FileNotFoundError:
            raise RuntimeError("Neither Docker nor Podman is installed.")


def is_responsive(ip_address, port):
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            return True
        else:
            return False
        sock.close()
    except Exception:
        return False


def wait_until_services_ready(ip_addresses, port):
    import time

    while not all(map(lambda i: is_responsive(i, port), ip_addresses)):
        time.sleep(0.1)


@pytest.fixture(scope="session")
def samba_server_pool():
    engine = detect_container_engine()

    ip_range = "127.1.0."
    config_dir = TEST_DIR / "shares"
    share_dir = TEST_DIR / "shares"

    containers = []
    ip_addresses = []
    ip_address_counter = 1

    for config_file in glob.glob(f"{config_dir}/*_config.json"):
        assert ip_address_counter < 255
        ip_address = ip_range + str(ip_address_counter)

        fp = open(config_file, "r")
        for config in json.load(fp)["configs"]:
            container_id = config
            config_file_base = Path(config_file).name
            container_name = spin_up_samba(
                engine, ip_address, share_dir, config_file_base, container_id
            )

            ip_addresses.append(ip_address)
            containers.append(container_name)
            ip_address_counter += 1

    wait_until_services_ready(ip_addresses, 445)

    yield ip_addresses

    # Stop and remove the containers
    for container in containers:
        run_command(f"{engine} stop {container}")


def spin_up_samba(engine, ip_address, share_dir, config, container_id):
    command = (
        f"{engine} run -d --rm "
        f"-p {ip_address}:445:445 "
        f"-v {share_dir}:/share:z "
        f"-e SAMBACC_CONFIG=/share/{config} "
        f"-e SAMBA_CONTAINER_ID={container_id} "
        f"quay.io/samba.org/samba-server:latest run --setup=init-all smbd"
    )
    container_name = run_command(command)

    return container_name


def test_samba(samba_server_pool, tmp_path, caplog):
    from smbcrawler.__main__ import main

    caplog.set_level("DEBUG")
    main(
        "-o",
        str(tmp_path),
        "-u",
        "user1",
        "-p",
        "password1",
        "-D",
        "2",
        *samba_server_pool,
    )

    assert os.path.isfile(tmp_path / "smbcrawler_files.json")
    assert os.path.isfile(tmp_path / "smbcrawler_paths.grep")
    assert os.path.isfile(tmp_path / "smbcrawler.log")

    paths = open(tmp_path / "smbcrawler_paths.grep", "r").read()
    assert "hello-world.txt" in paths
