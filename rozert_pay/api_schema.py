def public_schema_pre_process_hook(endpoints):  # type: ignore
    result = []

    for endpoint in endpoints:
        if endpoint[0].startswith("/api/payment/v1"):
            result.append(endpoint)

    return result
