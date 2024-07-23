#!/bin/bash

# Настройки
REPO="bonzaf/https://github.com/bonzaf/my_repo/"
BRANCH="new-branch"
BASE="master"
TITLE="NetBox Update"
BODY="This pull request contains updates from NetBox."

# Клонирование репозитория
git clone https://github.com/$REPO.git
cd your_repository

# Создание новой ветки и внесение изменений
git checkout -b $BRANCH
# (Добавьте команды для внесения изменений в файлы, например, обновление конфигурации)
git commit -am "Update from NetBox"

# Пуш изменений и создание pull request
git push origin $BRANCH
gh pr create --repo $REPO --title "$TITLE" --body "$BODY" --base $BASE --head $BRANCH

