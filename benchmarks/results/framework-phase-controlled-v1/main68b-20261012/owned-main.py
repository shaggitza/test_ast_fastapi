from fastapi import FastAPI

app = FastAPI()

@app.on_event("startup")
def startup() -> None:
    pass

@app.on_event("shutdown")
def shutdown() -> None:
    pass
