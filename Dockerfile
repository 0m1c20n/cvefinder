FROM wappalyzer/cli:latest

RUN apk add --no-cache --virtual .build-deps python3-dev nano git && \
    apk add --no-cache --update python3 && \
    pip3 install --upgrade pip setuptools

ADD cvefinder.py cvefinder.py

RUN git clone https://github.com/cve-search/PyCVESearch

RUN pip3 install ./PyCVESearch

ENTRYPOINT []

CMD ["/bin/sh"]
