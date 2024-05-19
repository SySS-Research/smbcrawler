from pathlib import Path
import json
import os
import random
import shlex
import string
import subprocess

import pytest
from sqlite_to_json import sqliteToJson

from smbcrawler.app import CrawlerApp, Login


login1 = Login("user1", "WORKGROUP", "password1")
login2 = Login("user2", "WORKGROUP", "password2")

SECRETS = {
    "logon.bat": "net use X: \\\\fs.contoso.local\\share /user:admin secretpassword",
    "groups.xml": 'cpassword="eBlgSIVExs+BO8LOGVI6M5EXkfrpBOxfxIOvvHoNSm4="',
    "SAM": "",
    "domain_controller.vdx": "",
    "default.ini": "password=iloveyou",
    "unattend.xml": "       <Password><Value>secret</Value></Password>",
}


@pytest.fixture(scope="session")
def smb_configs():
    shares = {
        "secret": {
            "options": {
                "path": "/share/small",
                "valid users": "user0",
                "invalid users": "user1, user2",
            }
        },
        "small": {"options": {"path": "/share/small", "valid users": "user1"}},
        "big": {"options": {"path": "/share/big", "valid users": "user1"}},
        "superbig": {"options": {"path": "/share/superbig", "valid users": "user1"}},
        "Admin$": {"options": {"path": "/share/big", "valid users": "user1"}},
    }

    users = {
        "all_entries": [
            {"name": "user1", "password": "password1"},
            {"name": "user2", "password": "password2"},
        ]
    }

    globals_ = {
        "noprinting": {
            "options": {
                "load printers": "no",
                "printing": "bsd",
                "printcap name": "/dev/null",
                "disable spoolss": "yes",
            }
        },
        "default": {
            "options": {
                "security": "user",
                "server min protocol": "SMB2",
                "map to guest": "never",
                "restrict anonymous": "2",
                "guest ok": "no",
            }
        },
        "allow_anonymous_listing": {
            "options": {
                "security": "user",
                "server min protocol": "SMB2",
                "map to guest": "bad user",
                "restrict anonymous": "0",
                "guest ok": "yes",
                "force user": "nobody",
                "guest account": "nobody",
            }
        },
        "allow_anonymous_share_access": {
            "options": {
                "security": "user",
                "server min protocol": "SMB2",
                "map to guest": "bad user",
                "restrict anonymous": "0",
                "force user": "user1",
                "guest account": "user1",
                "guest ok": "yes",
            }
        },
        "no_access": {
            "options": {
                "security": "domain",
                "server min protocol": "SMB2",
                "map to guest": "never",
                "restrict anonymous": "2",
                "guest ok": "no",
            },
        },
    }

    configs = {
        "base": {
            "shares": ["secret", "small", "Admin$"],
            "globals": ["noprinting", "default"],
            "instance_name": "SAMBA_BASE",
        },
        "anonymous_listing": {
            "shares": ["small"],
            "globals": ["noprinting", "allow_anonymous_listing"],
            "instance_name": "SAMBA_ANON_LIST",
        },
        "anonymous_read": {
            "shares": ["small"],
            "globals": ["noprinting", "allow_anonymous_share_access"],
            "instance_name": "SAMBA_ANON_READ",
        },
        "no_access": {
            "shares": ["small"],
            "instance_name": "SAMBA_ACCESS_DENIED",
        },
        "realistic": {
            "shares": ["small", "big", "superbig"],
            "globals": ["noprinting", "default"],
            "instance_name": "SAMBA_REALISTIC",
        },
    }

    config = {
        "samba-container-config": "v0",
        "configs": configs,
        "shares": shares,
        "users": users,
        "globals": globals_,
    }

    yield config


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


@pytest.fixture(scope="session")
def container_engine():
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


def create_random_file_structure(
    base_path, max_num_dirs, max_num_files, max_depth, secrets, current_depth=0
):
    if current_depth > max_depth:
        return
    # Decide randomly how many directories to create in this level
    num_dirs = random.randint(1, max_num_dirs)
    num_files = random.randint(0, max_num_files)

    for _ in range(num_dirs):
        dir_name = f"level_{current_depth}_"
        dir_name += "".join(random.choices(string.ascii_letters, k=10))
        new_dir_path = os.path.join(base_path, dir_name)
        os.makedirs(new_dir_path, exist_ok=True)
        create_random_file_structure(
            new_dir_path,
            max_num_dirs,
            max_num_files,
            max_depth,
            secrets,
            current_depth + 1,
        )

    for _ in range(num_files):
        file_name = f"level_{current_depth}_"
        file_name += "".join(random.choices(string.ascii_letters + string.digits, k=10))
        file_name += ".bin"

        file_path = os.path.join(base_path, file_name)
        file_size = random.randint(0, 64)
        with open(file_path, "wb") as fp:
            fp.write(os.urandom(file_size))

        # Create a secret
        if random.choice(range(20)) == 0:
            s = random.choice(list(secrets.keys()))
            file_path = os.path.join(base_path, s)

            with open(file_path, "w") as fp:
                for i in range(random.choice(range(10))):
                    line = (
                        "".join(
                            random.choices(
                                " " + string.ascii_letters + string.digits, k=10
                            )
                        )
                        + "\n"
                    )
                    fp.writelines(line)

                fp.writelines([secrets[s] + "\n"])

                for i in range(random.choice(range(10))):
                    line = (
                        "".join(
                            random.choices(
                                " " + string.ascii_letters + string.digits, k=10
                            )
                        )
                        + "\n"
                    )
                    fp.writelines(line)


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
    # It also sprinkles some files with secrets in there
    create_random_file_structure(tmp_path / "big", 3, 5, 3, SECRETS)
    create_random_file_structure(tmp_path / "superbig", 5, 8, 5, SECRETS)

    ip_range = "127.1.0."

    containers = []
    ip_addresses = {}
    ip_address_counter = 1

    config_file = tmp_path / "config.json"
    json.dump(smb_configs, open(config_file, "w"))

    try:
        fp = open(config_file, "r")
        for container_id, config in json.load(fp)["configs"].items():
            instances = config.get("instances", 1)
            config_file_base = Path(config_file).name

            for i in range(instances):
                assert ip_address_counter < 255
                ip_address = ip_range + str(ip_address_counter)
                container_name = spin_up_samba(
                    container_engine,
                    ip_address,
                    tmp_path,
                    config_file_base,
                    container_id,
                )

                ip_addresses[container_id] = ip_address
                containers.append(container_name)
                ip_address_counter += 1

        wait_until_services_ready(list(ip_addresses.values()), 445)

        yield ip_addresses

    finally:
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
    command = f"{engine} exec -it {container_name} chmod 755 /share"
    run_command(command)

    return container_name


@pytest.fixture(
    scope="session",
    params=[
        {"label": "base", "login": login1, "targets": None, "kwargs": {}},
        {
            "label": "full",
            "login": login1,
            "targets": None,
            "kwargs": {"depth": -1, "check_write_access": True},
        },
        {"label": "limited", "login": login1, "targets": None, "kwargs": {"depth": 4}},
    ],
)
def crawl_result(request, samba_server_pool, tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("output")

    from smbcrawler.log import init_logger

    init_logger()

    login = request.param["login"]
    targets = request.param["targets"] or list(samba_server_pool.values())
    kwargs = request.param["kwargs"]

    crawl_file = tmp_path / "smbcrawler.crwl"
    assert not os.path.isfile(crawl_file)

    app = CrawlerApp(
        login,
        targets=targets,
        crawl_file=crawl_file,
        **kwargs,
    )

    app.run()

    assert os.path.isfile(crawl_file)
    data = sqliteToJson(crawl_file)

    yield {
        "crawl_file": crawl_file,
        "data": data,
        "param": request.param,
    }


@pytest.fixture(scope="session")
def filter_crawl_result(request, crawl_result):
    criteria = request.param
    if all(crawl_result["param"].get(key) == value for key, value in criteria.items()):
        return crawl_result
    pytest.skip(f"No matching craw_result for criteria: {criteria}")
