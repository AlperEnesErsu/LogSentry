FROM ruby:3.4-alpine

RUN apk add --no-mkdir --no-cache build-base sqlite-dev tzdata

WORKDIR /app

COPY Gemfile* ./
RUN bundle install || true

COPY . .

EXPOSE 4567

CMD ["bin/logsentry"]
