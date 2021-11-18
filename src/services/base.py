from http import HTTPStatus
from typing import Union

from flask import Request, Response, make_response, jsonify
from pydantic import BaseModel, ValidationError

from core.utils import make_service_exception


class BaseService:
    def _validate(
            self, request: Request, model: BaseModel
            ) -> Union[BaseModel, Response]:
        request_json = request.json
        try:
            create_request = model(**request_json)
        except ValidationError as err:
            service_exception = make_service_exception(err)
            return make_response(
                jsonify(service_exception),
                HTTPStatus.BAD_REQUEST
            )
        return create_request
