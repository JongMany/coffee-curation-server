# 개발 stage에서 사용할 빌드 정의
# Dockerfile은 실행한 디렉토리 기준의 파일경로를 잡아온다.

## 어떤 이미지를 사용할지 
FROM node:alpine AS development 

## 작업 디렉토리 설정
WORKDIR /usr/src/app

## package.json / pnpm-lock.yaml 복사해오기
COPY package*.json ./
COPY pnpm-lock.yaml ./

## pnpm 설치
RUN npm i -g pnpm

## Dependency 설치하기 (pnpm)
RUN pnpm i

## 현재 폴더를 복사하기
COPY . .

## 커맨드 실행
CMD ["pnpm", "start:dev", "gateway"]