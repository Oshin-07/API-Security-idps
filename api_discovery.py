import httpx


HTTP_METHODS = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD"
]


def resolve_schema(schema, openapi_data):
    """
    Resolve a local OpenAPI $ref such as:
    #/components/schemas/User
    """

    if not schema:
        return {}

    if "$ref" in schema:

        ref = schema["$ref"]

        # OpenAPI 3
        if ref.startswith("#/components/schemas/"):

            schema_name = ref.split("/")[-1]

            return (
                openapi_data
                .get("components", {})
                .get("schemas", {})
                .get(schema_name, {})
            )

        # Swagger 2
        if ref.startswith("#/definitions/"):

            schema_name = ref.split("/")[-1]

            return (
                openapi_data
                .get("definitions", {})
                .get(schema_name, {})
            )

    return schema


def get_schema_type(schema, openapi_data=None):
    """
    Get the basic data type from an OpenAPI schema.
    """

    if not schema:
        return "unknown"

    if openapi_data:
        schema = resolve_schema(schema, openapi_data)

    if "type" in schema:
        return schema["type"]

    if "properties" in schema:
        return "object"

    if "$ref" in schema:
        return "object"

    return "unknown"


def extract_schema_properties(schema, openapi_data):
    """
    Extract fields from an object request body.
    """

    schema = resolve_schema(schema, openapi_data)

    properties = schema.get("properties", {})
    required_fields = schema.get("required", [])

    parameters = []

    for name, field_schema in properties.items():

        field_schema = resolve_schema(
            field_schema,
            openapi_data
        )

        parameters.append({
            "name": name,
            "location": "body",
            "type": get_schema_type(
                field_schema,
                openapi_data
            ),
            "required": name in required_fields
        })

    return parameters


def extract_parameters(
    operation,
    path_item,
    openapi_data
):
    """
    Extract query, path, header
    and request-body parameters.
    """

    parameters = []

    # Parameters defined at path level
    all_parameters = []

    all_parameters.extend(
        path_item.get("parameters", [])
    )

    all_parameters.extend(
        operation.get("parameters", [])
    )

    for param in all_parameters:

        schema = param.get("schema", {})

        # Swagger 2 style
        if not schema and "type" in param:
            schema = param

        # Resolve referenced schema
        schema = resolve_schema(
            schema,
            openapi_data
        )

        parameters.append({
            "name": param.get(
                "name",
                "unknown"
            ),
            "location": param.get(
                "in",
                "unknown"
            ),
            "type": get_schema_type(
                schema,
                openapi_data
            ),
            "required": param.get(
                "required",
                False
            )
        })

    # OpenAPI 3 request body
    request_body = operation.get(
        "requestBody"
    )

    if request_body:

        content = request_body.get(
            "content",
            {}
        )

        for content_type, content_data in content.items():

            schema = content_data.get(
                "schema",
                {}
            )

            schema = resolve_schema(
                schema,
                openapi_data
            )

            # Object with fields
            if schema.get("properties"):

                parameters.extend(
                    extract_schema_properties(
                        schema,
                        openapi_data
                    )
                )

            else:

                parameters.append({
                    "name": "request_body",
                    "location": "body",
                    "type": get_schema_type(
                        schema,
                        openapi_data
                    ),
                    "required": request_body.get(
                        "required",
                        False
                    )
                })

    return parameters


def get_authentication(
    openapi_data,
    operation
):
    """
    Identify authentication methods
    from OpenAPI security definitions.
    """

    security = operation.get(
        "security"
    )

    # If operation does not define security,
    # use global security settings
    if security is None:

        security = openapi_data.get(
            "security"
        )

    if not security:
        return None

    # OpenAPI 3
    schemes = openapi_data.get(
        "components",
        {}
    ).get(
        "securitySchemes",
        {}
    )

    # Swagger 2 compatibility
    if not schemes:

        schemes = openapi_data.get(
            "securityDefinitions",
            {}
        )

    auth_methods = []

    for security_requirement in security:

        for scheme_name in security_requirement:

            scheme = schemes.get(
                scheme_name,
                {}
            )

            scheme_type = scheme.get(
                "type"
            )

            if scheme_type == "http":

                auth_methods.append(
                    f"{scheme_name} "
                    f"({scheme.get('scheme', 'http')})"
                )

            elif scheme_type == "apiKey":

                auth_methods.append(
                    f"{scheme_name} (API Key)"
                )

            elif scheme_type == "oauth2":

                auth_methods.append(
                    f"{scheme_name} (OAuth2)"
                )

            elif scheme_type == "basic":

                auth_methods.append(
                    f"{scheme_name} (Basic)"
                )

            elif scheme_type:

                auth_methods.append(
                    f"{scheme_name} "
                    f"({scheme_type})"
                )

            else:

                auth_methods.append(
                    scheme_name
                )

    return (
        ", ".join(auth_methods)
        if auth_methods
        else None
    )


async def discover_api(swagger_url):
    """
    Download and analyze an
    OpenAPI / Swagger JSON document.
    """

    async with httpx.AsyncClient(
        timeout=15.0
    ) as client:

        response = await client.get(
            swagger_url
        )

        response.raise_for_status()

        openapi_data = response.json()

    endpoints = []

    paths = openapi_data.get(
        "paths",
        {}
    )

    for path, path_item in paths.items():

        for method in HTTP_METHODS:

            operation = path_item.get(
                method.lower()
            )

            if not operation:
                continue

            parameters = extract_parameters(
                operation,
                path_item,
                openapi_data
            )

            authentication = get_authentication(
                openapi_data,
                operation
            )

            endpoints.append({
                "path": path,
                "method": method,
                "parameters": parameters,
                "authentication": authentication
            })

    return {
        "api_url": swagger_url,
        "title": openapi_data.get(
            "info",
            {}
        ).get(
            "title"
        ),
        "version": openapi_data.get(
            "info",
            {}
        ).get(
            "version"
        ),
        "endpoints": endpoints
    }