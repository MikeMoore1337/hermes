"""Strict non-secret local configuration for a personal Linux device."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from device_fabric.linux_personal_sandbox import _project_path, validate_projects
from device_fabric.linux_personal_status import IDENTITIES
from device_fabric.native_brc_enrollment import _unique

SCHEMA = 'h454-linux-personal-device-v1'
MULTI_SCHEMA = 'h454-linux-personal-device-v2'
SHA40 = re.compile(r'[a-f0-9]{40}\Z')
SHA64 = re.compile(r'[a-f0-9]{64}\Z')
FIELDS = frozenset({'schema', 'target', 'device_id', 'project', 'release_sha',
                    'trust_release_sha', 'bundle_sha256'})


class PersonalLinuxConfigDenied(ValueError):
    """Never include a project path, bearer or configuration in a denial."""


@dataclass(frozen=True, slots=True, repr=False)
class PersonalLinuxConfig:
    target: str
    device_id: str
    project: str
    release_sha: str
    trust_release_sha: str
    bundle_sha256: str
    additional_projects: tuple[tuple[str, str], ...] = ()

    @property
    def bundle(self) -> str:
        return '/opt/hermes-commander-personal/releases/main-' + self.release_sha

    def __repr__(self) -> str:
        return 'PersonalLinuxConfig([REDACTED])'


def parse(raw: bytes, *, target: str) -> PersonalLinuxConfig:
    """Reject duplicate fields, noncanonical JSON and cross-host identities."""
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= 8192 or
                type(target) is not str or target not in IDENTITIES):
            raise ValueError()
        data = json.loads(raw.decode('ascii'), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(data) is not dict or data.get('schema') not in (SCHEMA, MULTI_SCHEMA) or
            set(data) != (FIELDS if data['schema'] == SCHEMA else FIELDS | {'projects'}) or
            data['target'] != target or type(data['device_id']) is not str or
            IDENTITIES[target].fullmatch(data['device_id']) is None or
            type(data['release_sha']) is not str or SHA40.fullmatch(data['release_sha']) is None or
            type(data['trust_release_sha']) is not str or SHA40.fullmatch(data['trust_release_sha']) is None or
            type(data['bundle_sha256']) is not str or SHA64.fullmatch(data['bundle_sha256']) is None or
            json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') != raw):
            raise ValueError()
        _project_path(data['project'])
        additional = ()
        if data['schema'] == MULTI_SCHEMA:
            items = data['projects']
            if (type(items) is not list or not 1 <= len(items) <= 4 or
                    any(type(item) is not dict or set(item) != {'name', 'path'} for item in items)):
                raise ValueError()
            additional = tuple((item['name'], item['path']) for item in items)
            validate_projects(data['project'], additional)
            if [item[0] for item in additional] != sorted(item[0] for item in additional):
                raise ValueError()
        return PersonalLinuxConfig(target, data['device_id'], data['project'], data['release_sha'],
                                   data['trust_release_sha'], data['bundle_sha256'], additional)
    except Exception:
        raise PersonalLinuxConfigDenied('personal_linux_config_denied') from None
