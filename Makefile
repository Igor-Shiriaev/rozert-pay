up:
	WEB_PORT=8006 docker compose up

pytest:
	pytest tests $(ARGS)

swagger:
	poetry run python manage.py spectacular --color --file swagger.yml

mypy:
	poetry run mypy rozert_pay/payment/systems

lint:
	poetry run pre-commit run --all-files

pylint:
	poetry run pylint .


########################################################

dev-build:
	WEB_PORT=8006 docker compose build --build-arg ENV=dev

dev-up:
	WEB_PORT=8006 docker compose up

dev-web-bash:
	docker compose run --rm -e DJANGO_SETTINGS_MODULE=rozert_pay.settings_unittest back bash

dev-fill-db:
	docker compose exec back poetry run python manage.py fill_dev_db
