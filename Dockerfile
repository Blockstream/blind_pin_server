FROM debian:buster@sha256:33a8231b1ec668c044b583971eea94fff37151de3a1d5a3737b08665300c8a0b

RUN apt update -qq && apt upgrade --no-install-recommends -yqq \
  && apt install --no-install-recommends -yqq procps python3-pip uwsgi uwsgi-plugin-python3 python3-setuptools nginx runit \ 
  && mkdir /etc/service/nginx \
  && mkdir /etc/service/wsgi

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx.runit /etc/service/nginx/run
COPY wsgi.runit /etc/service/wsgi/run

WORKDIR /pinserver
COPY runit_boot.sh wsgi.ini requirements.txt wsgi.py server.py lib.py pindb.py __init__.py generateserverkey.py flaskserver.py /pinserver/
RUN pip3 install --upgrade pip wheel
RUN pip3 install --require-hashes -r /pinserver/requirements.txt

CMD ["./runit_boot.sh"]
