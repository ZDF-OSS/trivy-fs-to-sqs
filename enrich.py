def enrich_payload(scan_payload, account_id, system_name, app_name):
    """
    Enriches the scan payload with additional metadata.

    Parameters:
        scan_payload (dict): The original scan payload to be enriched.
        account_id (str): AWS account ID.
        cluster_name (str): The name of the Kubernetes cluster.
        container_name (str): The name of the container.

    Returns:
        dict: The enriched scan payload.
    """
    enriched_payload = scan_payload.copy()  # Copy the original payload to avoid mutating the input
    enriched_payload.update({
        "DocumentType": "EFS",
        "AccountId": account_id,
        "DocumentVersion": 1,
        "SystemName": system_name,
        "InternalName": app_name
    })

    return enriched_payload
