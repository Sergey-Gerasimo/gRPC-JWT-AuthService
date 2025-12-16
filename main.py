import asyncio

from service.auth_interceptor import AuthInterceptor
from service.server import serve
from config import settings
from database import AsyncSessionLocal, async_engine, create_tables
from repository.redis_repository import RedisRepository, RedisConnectionPool
from repository.user_repository import UserRepository
from service.jwt_service import JWTService
from service.auth_service import AuthService
from service.user_service import UserService


if __name__ == "__main__":

    async def _run():

        session = AsyncSessionLocal()
        cache_repository = RedisRepository()
        user_repository = UserRepository(session=session)
        jwt_service = JWTService(
            access_token_expire_minutes=settings.security.access_token_expire_minutes,
            refresh_token_expire_minutes=settings.security.refresh_token_expire_minutes,
            secret_key=settings.security.secret_key,
            algorithm=settings.security.algorithm,
        )
        auth_service = AuthService(
            cache_repository=cache_repository,
            user_repository=user_repository,
            jwt_service=jwt_service,
        )

        auth_interceptor = AuthInterceptor(
            jwt_service=jwt_service,
            user_repository=user_repository,
            cache_repository=cache_repository,
        )

        user_service = UserService(user_repository=user_repository)

        await create_tables(async_engine)
        try:
            await serve(
                auth_service=auth_service,
                user_service=user_service,
                auth_interceptor=auth_interceptor,
            )
        finally:
            await session.close()
            await async_engine.dispose()
            await RedisConnectionPool.close_pool()

    asyncio.run(_run())
