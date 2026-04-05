FROM cgr.dev/chainguard/python:latest-dev as dev

WORKDIR /app

RUN python -m venv venv
ENV PATH="/app/venv/bin:$PATH"
COPY app/requirements.txt requirements.txt
RUN pip install -r requirements.txt

FROM cgr.dev/chainguard/python:latest

WORKDIR /app

COPY app/ /app/
COPY --from=dev /app/venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

CMD [ "python", "init_db.py" ]

ENTRYPOINT ["python", "app.py"]