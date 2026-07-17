from __future__ import annotations

from fastapi import APIRouter, Depends, status

from .dependencies import get_current_user
from .schemas import LoginRequest, RefreshTokenRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def login(payload: LoginRequest):
    raise NotImplementedError("Login endpoint logic must be implemented.")


@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def refresh(payload: RefreshTokenRequest):
    raise NotImplementedError("Refresh endpoint logic must be implemented.")


@router.get("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
def me(user=Depends(get_current_user)):
    return user
