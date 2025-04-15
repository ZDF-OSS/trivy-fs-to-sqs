from kubernetes import client, config
import subprocess
import logging
from typing import List


def check_trivy_installed() -> bool:
    result = subprocess.run(
        ["trivy", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.returncode == 0
