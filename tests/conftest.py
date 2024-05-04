import subprocess
import shlex

import pytest


@pytest.fixture(scope="session")
def smb_configs():
    shares = {
        "small": {"options": {"path": "/share/small", "valid users": "user1"}},
        "big": {"options": {"path": "/share/big", "valid users": "user1"}},
        "superbig": {"options": {"path": "/share/superbig", "valid users": "user1"}},
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
                "map to guest": "never",
                "restrict anonymous": "0",
                "guest ok": "no",
            }
        },
        "allow_anonymous_share_access": {
            "options": {
                "map to guest": "bad user",
                "restrict anonymous": "0",
                "guest ok": "yes",
            }
        },
    }

    configs = {
        "base": {
            "shares": ["small"],
            "globals": ["noprinting", "default"],
            "instance_name": "SAMBA_BASE",
        },
        "anonymous_listing": {
            "shares": ["small"],
            "globals": ["noprinting", "default", "allow_anonymous_listing"],
            "instance_name": "SAMBA_ANON_LIST",
        },
        "anonymous_read": {
            "shares": ["small"],
            "globals": ["noprinting", "default", "allow_anonymous_share_access"],
            "instance_name": "SAMBA_ANON_READ",
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
