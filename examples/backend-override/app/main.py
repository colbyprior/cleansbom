import requests
from fastapi import FastAPI
from jinja2 import Template

app = FastAPI()


@app.get("/hello")
def hello():
    return {"msg": Template("hello from {{ who }}").render(who="python")}


@app.get("/upstream")
def upstream():
    return {"status": requests.get("https://example.com", timeout=5).status_code}
