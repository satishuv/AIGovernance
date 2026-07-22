"""
Seed Tables Lambda, bulk-loads DynamoDB tables during CDK deployment.

Accepts an event with a `seeds` array. Each entry contains:
  - table_name: the physical DynamoDB table name
  - items: list of dicts (native Python types, not DynamoDB JSON)

Uses boto3 DynamoDB *resource* (Table.batch_writer) so items are plain dicts.
"""

import json
import logging

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")


def handler(event, context):
    """Seed multiple DynamoDB tables in a single invocation."""
    logger.info("Seed tables Lambda invoked")

    seeds = event.get("seeds", [])
    if not seeds:
        logger.warning("No seeds provided in event payload")
        return {"status": "NO_OP", "message": "No seeds provided"}

    results = []
    total_items = 0
    errors = []

    for seed in seeds:
        table_name = seed.get("table_name")
        items = seed.get("items", [])

        if not table_name:
            errors.append("Seed entry missing 'table_name'")
            continue
        if not items:
            logger.info("Skipping table %s, no items", table_name)
            continue

        try:
            table = dynamodb.Table(table_name)
            written = 0
            with table.batch_writer() as batch:
                for item in items:
                    batch.put_item(Item=item)
                    written += 1

            total_items += written
            results.append({
                "table_name": table_name,
                "items_written": written,
                "status": "OK",
            })
            logger.info("Wrote %d items to %s", written, table_name)

        except Exception as exc:
            msg = f"Error seeding {table_name}: {exc}"
            logger.error(msg)
            errors.append(msg)
            results.append({
                "table_name": table_name,
                "status": "ERROR",
                "error": str(exc),
            })

    status = "SUCCESS" if not errors else "PARTIAL_FAILURE"
    response = {
        "status": status,
        "total_items_written": total_items,
        "tables_processed": len(results),
        "results": results,
    }
    if errors:
        response["errors"] = errors

    logger.info("Seed complete: %s", json.dumps(response))
    return response
