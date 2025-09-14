from fastapi import FastAPI

app = FastAPI(title="u-social API")


@app.get("/")
def read_root():
    return {"message": "Welcome to the u-social API"}


# Later, we will include routers from the `routers` directory
# from .routers import users, posts
#
# app.include_router(users.router)
# app.include_router(posts.router)
