#### AUTH Service

OpenAPI design: `/design/authservice_openapi.yaml`

**Deployment instructions:**

1. Create .env file with sample (change default passwords!):

`$ mv env.sample .env`

`$ vi .env`

3. Run project with tests:

`$ docker-compose --profile=testing up --build`

4. Run project without tests:

`$ docker-compose up --build`

5.Clear up docker:

`$ docker-compose down -v`
