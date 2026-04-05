"""Step-up authentication FastAPI dependency.

Usage:
    from app.middleware.stepup import require_step_up

    @router.post("/sensitive-action", dependencies=[Depends(require_step_up("policy.escrow.enable"))])
    async def sensitive_action(...):
        ...

Or as an explicit dependency to get the verified token payload:
    @router.post("/sensitive-action")
    async def sensitive_action(
        _: None = Depends(require_step_up("policy.escrow.enable")),
        ...
    ):
        ...

When the function_key is NOT currently marked sensitive in sensitive_config,
the dependency is a no-op and allows the request through unchanged — no code
changes are needed if a function's sensitivity flag changes at setup time.
"""

import logging

from fastapi import Depends, HTTPException, Request

import app.sensitive_config as sensitive_config
from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.auth.stepup import verify_step_up_token

logger = logging.getLogger(__name__)

_STEP_UP_TOKEN_HEADER = "X-Step-Up-Token"


def require_step_up(action_key: str):
    """Return a FastAPI dependency that enforces step-up auth for action_key.

    If the action is not marked sensitive in the current sensitive_config, the
    dependency is a transparent no-op — the request proceeds normally.

    If the action IS sensitive and no valid step-up token is present, returns:
      HTTP 403 {
        "error": "step_up_required",
        "action": "<action_key>",
        "challenge_type": "password" | "totp" | "webauthn"
      }

    The client should show the appropriate challenge, POST to /auth/step-up,
    then retry the original request with X-Step-Up-Token: <token>.
    """

    async def _dependency(
        request: Request,
        user: AuthenticatedUser = Depends(require_user_role),
    ) -> None:
        if not sensitive_config.is_sensitive(action_key):
            return  # Not sensitive — allow through

        token = request.headers.get(_STEP_UP_TOKEN_HEADER, "")
        if not token:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "step_up_required",
                    "action": action_key,
                    "challenge_type": sensitive_config.get_challenge_type(action_key),
                },
            )

        if not verify_step_up_token(token, user.id, action_key):
            logger.warning(
                "Invalid step-up token: user=%s action=%s", user.id, action_key
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "step_up_invalid",
                    "action": action_key,
                    "challenge_type": sensitive_config.get_challenge_type(action_key),
                },
            )

    return _dependency
