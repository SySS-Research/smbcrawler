from pathlib import Path
import json
import os
import pytest
import random
import shlex
import string
import subprocess


TEST_DIR = Path(__file__).resolve().parent


def create_random_file_structure(
    base_path, max_num_dirs, max_num_files, max_depth, current_depth=0
):
    if current_depth > max_depth:
        return
    # Decide randomly how many directories to create in this level
    num_dirs = random.randint(0, max_num_dirs)
    num_files = random.randint(0, max_num_files)

    for _ in range(num_dirs):
        dir_name = "".join(random.choices(string.ascii_letters, k=10))
        new_dir_path = os.path.join(base_path, dir_name)
        os.makedirs(new_dir_path, exist_ok=True)
        create_random_file_structure(
            new_dir_path, max_num_dirs, max_num_files, max_depth, current_depth + 1
        )

    for _ in range(num_files):
        file_name = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        file_path = os.path.join(base_path, file_name)
        file_size = random.randint(0, 64)
        with open(file_path, "wb") as f:
            f.write(os.urandom(file_size))


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

    total = 0
    while not all(map(lambda i: is_responsive(i, port), ip_addresses)):
        time.sleep(0.1)
        total += 1
        if total > 20:
            raise RuntimeError("Timeout: Services not ready")


@pytest.fixture(scope="session")
def samba_server_pool(smb_configs, tmp_path_factory, container_engine):
    random.seed(0)
    tmp_path = tmp_path_factory.mktemp("smb")

    # Create file trees in share directories
    for share in ["small", "big", "superbig"]:
        os.mkdir(tmp_path / share)
    open(tmp_path / "small" / "hello-world.txt", "w").write("Hello!\n")
    # This generates about 5MB worth of data in 794 files and 517 directories.
    create_random_file_structure(tmp_path / "big", 3, 5, 3)
    create_random_file_structure(tmp_path / "superbig", 5, 8, 5)

    ip_range = "127.1.0."

    containers = []
    ip_addresses = []
    ip_address_counter = 1

    config_file = tmp_path / "config.json"
    json.dump(smb_configs, open(config_file, "w"))

    fp = open(config_file, "r")
    for container_id, config in json.load(fp)["configs"].items():
        instances = config.get("instances", 1)
        config_file_base = Path(config_file).name

        for i in range(instances):
            assert ip_address_counter < 255
            ip_address = ip_range + str(ip_address_counter)
            container_name = spin_up_samba(
                container_engine, ip_address, tmp_path, config_file_base, container_id
            )

            ip_addresses.append(ip_address)
            containers.append(container_name)
            ip_address_counter += 1

    wait_until_services_ready(ip_addresses, 445)

    yield ip_addresses

    # Stop and remove the containers
    for container in containers:
        try:
            run_command(f"{container_engine} stop {container} -t 0")
        except Exception:
            pass


def spin_up_samba(engine, ip_address, share_dir, config, container_id):
    assert " " not in config
    assert " " not in container_id
    assert " " not in ip_address
    img = "quay.io/samba.org/samba-server:latest"
    command = (
        f"{engine} run -d --rm "
        f"-p {ip_address}:445:445 "
        f"-v {share_dir}:/share:z "
        f"-e SAMBACC_CONFIG=/share/{config} "
        f"-e SAMBA_CONTAINER_ID={container_id} "
        f"{img} run --setup=init-all smbd"
    )
    print(command)
    container_name = run_command(command)
    # fix permissions. not sure why this is necessary.
    command = (
        f"{engine} exec -it {container_name} chmod 755 /share"
    )
    run_command(command)

    return container_name


def test_samba(samba_server_pool, tmp_path, caplog, monkeypatch):
    monkeypatch.chdir(tmp_path)

    from smbcrawler.app import CrawlerApp, Login

    caplog.set_level("DEBUG")

    login = Login(
        "user1",
        "WORKGROUP",
        "password1",
    )

    app = CrawlerApp(
        login,
        targets=samba_server_pool,
    )

    app.run()

    assert os.path.isfile(tmp_path / "smbcrawler.crwl")
