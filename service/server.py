import asyncio
from grpc import aio

from config import settings
from grpc_generated import auth_pb2_grpc
from service.auth_interceptor import AuthInterceptor


async def serve(*, auth_service, user_service, auth_interceptor: AuthInterceptor):
    host = settings.grpc.host
    port = settings.grpc.port

    server = aio.server(interceptors=[auth_interceptor])

    auth_pb2_grpc.add_AuthServiceServicer_to_server(auth_service, server)
    auth_pb2_grpc.add_UserServiceServicer_to_server(user_service, server)

    server.add_insecure_port(f"{host}:{port}")
    await server.start()

    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        await server.stop(0)
    finally:
        await server.stop(0)
