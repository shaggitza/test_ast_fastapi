from fastapi import FastAPI
app = FastAPI()
def startup_helper() -> str:
    return 'baseline'
@app.on_event('startup')
async def startup() -> None:
    startup_helper()
@app.on_event('shutdown')
async def shutdown() -> None:
    pass
@app.get('/probe')
async def probe() -> dict[str, bool]:
    return {'ok': True}
