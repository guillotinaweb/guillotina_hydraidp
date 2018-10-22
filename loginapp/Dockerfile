FROM node:8.9.4-alpine

COPY . /ng-app

WORKDIR /ng-app

RUN yarn global add @angular/cli
RUN yarn

ENTRYPOINT ["ng", "serve", "--host=0.0.0.0", "--disable-host-check"]
