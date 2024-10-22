from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from .schemas import UserCreateModel, UserModel, UserLoginModel
from .service import UserService
from src.db.main import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from .utils import create_access_token, decode_token, verify_password
from datetime import timedelta


auth_router = APIRouter()
user_service = UserService()

REFRESH_TOKEN_EXPIRE = 2


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
async def login_users(login_data: UserLoginModel, session: AsyncSession = Depends(get_session)):
    email = login_data.email
    password = login_data.password
    user = await user_service.get_user_by_email(email, session)

    if user is not None:
        password_valid = verify_password(password, user.password_hash)

        if password_valid:
            access_token = create_access_token(
                user_data={
                    "email": user.email,
                    "user_uuid": str(user.uid)
                }
            )
            refresh_token = create_access_token(
                user_data={
                    "email": user.email,
                    "user_uuid": str(user.uid)
                },
                refresh=True,
                expire=timedelta(days=REFRESH_TOKEN_EXPIRE),
            )

            return JSONResponse(
                content= {
                    "message": "login successfully",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "email": user.email,
                        "uid": str(user.uid),
                    }
                }
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
    )