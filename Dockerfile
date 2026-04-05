FROM cgr.dev/chainguard/python:3.12

WORKDIR /app

COPY app/ /app/

RUN pip install -r requirements.txt

RUN python init_db.py

CMD [ "python", "app.py" ]