"""
Bridge to the LOCAL FRRouting lab containers (router-a, router-b).

Cross-validation method
-----------------------
No live BGP session is needed: FRR's own prefix-list parser/matcher is the
reference oracle. For each probe we run, inside the container,

    vtysh -c "show ip prefix-list NAME match PREFIX"
    vtysh -c "show ipv6 prefix-list NAME match PREFIX"

which prints FRR's decision (matching seq / allow / deny). The prefix list
itself is installed from a snapshot's rendered config and removed again
after the run.

Transports
----------
* "docker" (default in compose labs): `docker exec rpolicy-router-X vtysh ...`
* "ssh"   : optional, when docker is not reachable from the API process
            (set RLAB_FRR_TRANSPORT=ssh; see config.py for host/port)

The lab network is an internal bridge with no production connectivity.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

import paramiko

from .config import (
    FRR_HOST_A, FRR_HOST_B, FRR_SSH_PORT_A, FRR_SSH_PORT_B,
    FRR_SSH_USER, FRR_SSH_PASSWORD,
    FRR_LOCAL_VTYSH, FRR_LOCAL_VTY_SOCKET, FRR_LOCAL_CONFIG_DIR,
    FRR_LOCAL_DAEMON, FRR_LOCAL_ENV,
)
from .engine import Policy

FRR_TRANSPORT = os.environ.get("RLAB_FRR_TRANSPORT", "docker").lower()


class FRRUnavailable(RuntimeError):
    pass


@dataclass
class FRRObservation:
    prefix: str
    action: str           # permit / deny / error
    seq: Optional[int]
    raw: str


NODES = {
    "a": {"docker": "rpolicy-router-a", "host": FRR_HOST_A, "port": FRR_SSH_PORT_A},
    "b": {"docker": "rpolicy-router-b", "host": FRR_HOST_B, "port": FRR_SSH_PORT_B},
}


class FRRBridge:
    def __init__(self, node: str = "a",
                 transport: Optional[str] = None,
                 username: str = FRR_SSH_USER, password: str = FRR_SSH_PASSWORD,
                 timeout: float = 20.0):
        self.node = node
        self.transport = (transport or FRR_TRANSPORT).lower()
        meta = NODES.get(node, NODES["a"])
        self.container = meta["docker"]
        self.host, self.port = meta["host"], meta["port"]
        self.username, self.password = username, password
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    # ------------------------------------------------------------- transport
    def connect(self) -> "FRRBridge":
        if self.transport == "docker":
            if not shutil.which("docker"):
                raise FRRUnavailable(
                    "docker CLI not found; start the API host with docker access "
                    "or set RLAB_FRR_TRANSPORT=ssh|local"
                )
            try:
                self._docker(["true"])
            except FRRUnavailable:
                raise FRRUnavailable(
                    f"container {self.container!r} not running. "
                    "Start: docker compose -f frr/docker-compose.yml up -d"
                )
        elif self.transport == "local":
            # native vtysh against a unix vty socket on this host (no docker)
            if not os.path.exists(FRR_LOCAL_VTYSH):
                if not shutil.which(FRR_LOCAL_VTYSH):
                    raise FRRUnavailable(
                        f"local vtysh {FRR_LOCAL_VTYSH!r} not found")
            try:
                self._local(["show version"])
            except FRRUnavailable:
                raise FRRUnavailable(
                    f"local FRR at socket {FRR_LOCAL_VTY_SOCKET!r} unreachable")
        elif self.transport == "ssh":
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=self.host, port=self.port,
                    username=self.username, password=self.password,
                    timeout=self.timeout, allow_agent=False, look_for_keys=False,
                )
            except (OSError, paramiko.SSHException) as e:
                raise FRRUnavailable(
                    f"FRR node '{self.node}' at {self.host}:{self.port} unreachable: {e}") from e
            self._client = client
        else:
            raise FRRUnavailable(f"unknown transport {self.transport!r}")
        return self

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    def _docker(self, argv: List[str], allow_warning_rc: bool = False) -> str:
        cmd = ["docker", "exec", self.container] + argv
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            raise FRRUnavailable(f"docker exec timeout: {' '.join(argv)}") from e
        except OSError as e:
            raise FRRUnavailable(f"docker exec failed: {e}") from e
        # FRR returns CMD_WARNING (1) for an oracle DENY result
        if p.returncode != 0 and not (allow_warning_rc and p.returncode == 1):
            raise FRRUnavailable(
                f"docker exec rc={p.returncode}: {p.stderr.strip() or p.stdout.strip()}")
        return p.stdout + p.stderr

    def _local_env(self) -> dict:
        env = os.environ.copy()
        for pair in FRR_LOCAL_ENV.split(","):
            pair = pair.strip()
            if pair and "=" in pair:
                k, v = pair.split("=", 1)
                env[k] = v
        return env

    def _local(self, argv: List[str]) -> str:
        args = [FRR_LOCAL_VTYSH, "--config_dir", FRR_LOCAL_CONFIG_DIR,
                "--vty_socket", FRR_LOCAL_VTY_SOCKET,
                "-d", FRR_LOCAL_DAEMON]
        for c in argv:
            args += ["-c", c]
        try:
            p = subprocess.run(args, capture_output=True, text=True,
                               timeout=self.timeout, env=self._local_env(),
                               input="")
        except subprocess.TimeoutExpired as e:
            raise FRRUnavailable(
                f"local vtysh timeout: {' '.join(argv)}") from e
        except OSError as e:
            raise FRRUnavailable(f"local vtysh failed: {e}") from e
        if p.returncode not in (0, 1):
            raise FRRUnavailable(
                f"local vtysh rc={p.returncode}: "
                f"{p.stderr.strip() or p.stdout.strip()}")
        return p.stdout + p.stderr

    def vtysh(self, commands: List[str], allow_warning_rc: bool = False) -> str:
        if self.transport == "docker":
            args = []
            for c in commands:
                args += ["-c", c]
            return self._docker(["vtysh"] + args, allow_warning_rc=allow_warning_rc)

        if self.transport == "local":
            return self._local(commands)

        # ssh
        assert self._client is not None, "not connected"
        args = " ".join(f"-c {_shell_quote(c)}" for c in commands)
        _stdin, stdout, stderr = self._client.exec_command(
            f"vtysh {args}", timeout=self.timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        # FRR returns CMD_WARNING (1) for a DENY oracle result
        if rc != 0 and not (allow_warning_rc and rc == 1):
            raise FRRUnavailable(f"vtysh rc={rc}: {err.strip() or out.strip()}")
        return out + err

    # ------------------------------------------------------------- provision
    def install_policy(self, policy: Policy, vrf: str = "") -> str:
        cmds = ["configure terminal"]
        if vrf:
            cmds.append(f"vrf {vrf}")
        cmds += policy.to_frr_prefix_list().splitlines()
        cmds += ["end", "write memory"]
        return self.vtysh(cmds)

    def remove_policy(self, name: str, family: int, vrf: str = "") -> str:
        ip = "ip" if family == 4 else "ipv6"
        cmds = ["configure terminal"]
        if vrf:
            cmds.append(f"vrf {vrf}")
        cmds.append(f"no {ip} prefix-list {name}")
        cmds += ["end", "write memory"]
        return self.vtysh(cmds)

    def show_prefix_list(self, name: str, family: int) -> str:
        ip = "ip" if family == 4 else "ipv6"
        return self.vtysh([f"show {ip} prefix-list {name}"])

    # -------------------------------------------------------------- observe
    # FRR reference oracle (verified against FRR 8.5/8.4 source, plist.c):
    #
    #   debug ip prefix-list WORD match A.B.C.D/M
    #       -> "ip prefix list WORD yields PERMIT|DENY for P,
    #           matching entry #SEQ: P[/M ge X le Y]"  or  "no match found"
    #   (returns vtysh exit code 0 on PERMIT, CMD_WARNING(1) on DENY)
    #
    # Caveat baked into FRR itself: a plist that EXISTS BUT HAS ZERO ENTRIES
    # yields PREFIX_PERMIT. FRR has no implicit deny; that default is a
    # property of the calling route-map/BGP policy. Our snapshots always
    # carry explicit rules; validate.py normalizes the comparison.
    _YIELDS_RE = re.compile(r"yields\s+(PERMIT|DENY)", re.IGNORECASE)
    _SEQ_RE = re.compile(r"matching entry #(\d+)", re.IGNORECASE)

    def observe(self, policy_name: str, family: int, prefix: str,
                vrf: str = "") -> FRRObservation:
        ip = "ip" if family == 4 else "ipv6"
        # FRR 8.5+ and the container lab (8.4.1 images) accept
        #   debug {ip|ipv6} prefix-list NAME match PREFIX
        # the Debian-native 8.4.x build instead exposes the oracle under
        #   debug prefix-list NAME match PREFIX
        # Try the ip/ipv6 form first, fall back when the CLI rejects it.
        probe = f"debug {ip} prefix-list {policy_name} match {prefix}"
        cmds = [f"vrf {vrf}", probe] if vrf else [probe]
        # PERMIT -> rc 0, DENY -> CMD_WARNING(1), so do not treat rc!=0 as
        # a transport error: parse both streams.
        raw = self.vtysh(cmds, allow_warning_rc=True)
        if "Unknown command" in raw or "no matched command" in raw.lower():
            probe2 = f"debug prefix-list {policy_name} match {prefix}"
            cmds = [f"vrf {vrf}", probe2] if vrf else [probe2]
            raw = self.vtysh(cmds, allow_warning_rc=True)

        m = self._YIELDS_RE.search(raw)
        action = "error"
        if m:
            action = "permit" if m.group(1).lower() == "permit" else "deny"
        seqm = self._SEQ_RE.search(raw)
        return FRRObservation(
            prefix=prefix, action=action,
            seq=int(seqm.group(1)) if seqm else None, raw=raw.strip(),
        )

    def ping(self) -> bool:
        try:
            self.connect()
            out = self.vtysh(["show version"])
            self.close()
            return "FRRouting" in out or "frr" in out.lower()
        except FRRUnavailable:
            return False


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"
