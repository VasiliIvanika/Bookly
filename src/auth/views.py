from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from .schemas import UserCreateModel, UserModel
from .service import UserService
from src.db.main import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from .utils import create_access_token, decode_token


auth_router = APIRouter()
user_service = UserService()


@auth_router.post(
    "/signup",
    response_model=UserModel,
    status_code=status.HTTP_201_CREATED,
)
async def create_user_Account(
        user_data: UserCreateModel,
        session: AsyncSession = Depends(get_session),
):
    email = user_data.email
    user_exist = await user_service.user_exist(email, session)

    if user_exist:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Some user already has this email",
        )
    new_user = await user_service.create_user(user_data, session)
    return new_user


@auth_router.post("/login")
async def login_users():
    pass