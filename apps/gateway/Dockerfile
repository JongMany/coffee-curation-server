## 어떤 이미지를 사용할지 
FROM node:alpine AS development 

## 작업 디렉토리 설정
WORKDIR /usr/src/app

## package.json / pnpm-lock.yaml 복사해오기
COPY package*.json ./
COPY pnpm-lock.yaml ./
COPY tsconfig.json tsconfig.json
COPY nest-cli.json nest-cli.json

## pnpm 설치
RUN npm i -g pnpm

## Dependency 설치하기 (pnpm)
RUN pnpm i

## 프로젝트 빌드에 필요한 폴더를 복사하기
COPY apps/gateway apps/gateway
COPY libs libs

RUN pnpm build gateway

## 커맨드 실행
CMD ["pnpm", "start:dev", "gateway"]

FROM node:alpine AS production

ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

WORKDIR /usr/src/app

COPY package*.json ./
COPY pnpm-lock.yaml ./

RUN npm install -g pnpm
RUN pnpm install --prod

COPY --from=development /usr/src/app/dist ./dist
COPY proto proto

CMD ["node", "dist/apps/gateway/main"]