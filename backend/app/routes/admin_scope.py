"""Admin scope enforcement helpers (Phase 1 permissions overhaul).

Scoped admins hold admin flags only within specific team(s).  These helpers
enforce that an admin's operation targets a resource inside their scope.

Usage pattern:

    from app.routes.admin_scope import require_team_scope, scope_team_ids

    @router.get("/teams/{team_id}/...")
    async def my_endpoint(
        team_id: str,
        admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    ):
        require_team_scope(admin, team_id, "can_manage_teams")
        ...

    # For list endpoints, limit to scoped teams:
    @router.get("/teams")
    async def list_teams(...):
        allowed = scope_team_ids(admin, "can_manage_teams")
        # allowed is None → org-wide admin, no filter; set → filter to those IDs
"""

from fastapi import HTTPException

from app.auth.interface import AuthenticatedUser


def require_team_scope(
    user: AuthenticatedUser,
    team_id: str,
    flag: str = "can_manage_teams",
) -> None:
    """Raise 403 if *user* does not hold *flag* within the given team scope.

    Org-wide holders of the flag (global role grant) pass unconditionally.
    Scoped team admins pass only if team_id is in their granted scope.
    """
    team_ids = user.get_team_ids_with_flag(flag)
    if team_ids is None:
        return  # org-wide grant → always allowed
    if team_id not in team_ids:
        raise HTTPException(
            status_code=403,
            detail=f"Admin scope does not include team {team_id}",
        )


def scope_team_ids(
    user: AuthenticatedUser,
    flag: str = "can_manage_teams",
) -> set[str] | None:
    """Return the set of team IDs the user may administer for *flag*.

    Returns None if the user is an org-wide admin (no restriction applies).
    Returns a (possibly empty) set for scoped admins.

    Callers should filter their query results to the returned set when it is
    not None:

        allowed = scope_team_ids(admin, "can_manage_teams")
        if allowed is not None and team_id not in allowed:
            raise HTTPException(404)  # hide out-of-scope teams
    """
    return user.get_team_ids_with_flag(flag)
