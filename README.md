#### AUTH Service

Ссылка на репозиторий: [https://github.com/simenshteyn/Auth_sprint_1](https://github.com/simenshteyn/Auth_sprint_1)

OpenAPI design: `/design/authservice_openapi.yaml`

**Setup**
1. Create .env file with sample (change the default passwords and secret keys!):

`$ mv env.sample .env`

`$ vi .env`

**Run project without tests**

standard Flask app:

`$ docker-compose up --build`

gevent-based Flask app:

`$ docker-compose -f docker-compose.yml -f docker-compose.prod.yml up --build`


**Testing**
 - Running tests against the *standard* Flask app:
   
`$ docker-compose --profile=testing up --build`
   
 - Running tests against *gevent-based* Flask app:
 
`$ docker-compose down -v`

**Execute superadmin console command:**

`$ docker exec --env FLASK_APP=main -it auth_app flask manage createsuperuser`
