# -*- coding: utf-8 -*-
"""Plus trial link extraction service configuration."""
from config.env_loader import apply_env_overrides

# Link extraction service address
EXTRACT_LINK_API_BASE: str = ""

# Link extraction CDK; required both for creating tasks and for listening to events.
EXTRACT_LINK_CDK: str = ""

# link extraction type:pix / upi / kakao_pay / ideal
EXTRACT_LINK_TYPE: str = "pix"

# Background link extraction concurrency and timeout
EXTRACT_LINK_WORKERS: int = 3
EXTRACT_LINK_QUEUE_LIMIT: int = 500
EXTRACT_LINK_REQUEST_TIMEOUT: int = 30
EXTRACT_LINK_EVENT_TIMEOUT: int = 180

apply_env_overrides(globals(), {
    'EXTRACT_LINK_API_BASE': 'str',
    'EXTRACT_LINK_CDK': 'str',
    'EXTRACT_LINK_TYPE': 'str',
    'EXTRACT_LINK_WORKERS': 'int',
    'EXTRACT_LINK_QUEUE_LIMIT': 'int',
    'EXTRACT_LINK_REQUEST_TIMEOUT': 'int',
    'EXTRACT_LINK_EVENT_TIMEOUT': 'int',
})
