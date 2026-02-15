"""Azure Functions entry point — triggers and activity function definitions."""

import logging
import os
from base64 import b64decode, b64encode

import azure.durable_functions as df
import azure.functions as func

from cert_manager.acme_client import complete_order, create_order
from cert_manager.config import load_config
from cert_manager.dns import get_dns_provider
from cert_manager.dns.util import split_record_name
from cert_manager.keyvault import scan_certificates, upload_certificate
from cert_manager.models import AcmeOrderContext, RenewalRequest

app = df.DFApp(http_auth_level=func.AuthLevel.FUNCTION)


# Timer trigger — starts the Durable orchestrator daily
@app.function_name("timer_start")
@app.timer_trigger(schedule="0 0 2 * * *", arg_name="timer", run_on_startup=False)
@app.durable_client_input(client_name="client")
async def timer_start(timer: func.TimerRequest, client: df.DurableOrchestrationClient) -> None:
    instance_id = await client.start_new("certificate_renewal_orchestrator")
    logging.info("Started orchestrator instance %s", instance_id)


# Orchestrator — placeholder for Stage 5
@app.orchestration_trigger(context_name="context")
def certificate_renewal_orchestrator(context: df.DurableOrchestrationContext):
    # Will be implemented in Stage 5
    return []


# Activity — scan Key Vault for certificates due for renewal
@app.activity_trigger(input_name="input")
def scan_keyvault_certificates(input: None) -> list[dict]:
    config = load_config()
    certs = scan_certificates(config)
    return [c.to_dict() for c in certs]


# Activity — upload renewed PFX to Key Vault
@app.activity_trigger(input_name="input")
def upload_certificate_to_keyvault(input: dict) -> None:
    config = load_config()
    upload_certificate(config, input["cert_name"], b64decode(input["pfx_b64"]))


# Activity — create ACME order and extract DNS-01 challenges
@app.activity_trigger(input_name="input")
def create_acme_order(input: dict) -> dict:
    request = RenewalRequest.from_dict(input)
    ctx = create_order(
        directory_url=request.acme_directory_url,
        contact_email=request.contact_email,
        domains=request.domains,
        account_key_json=os.environ.get("ACME_ACCOUNT_KEY"),
        account_uri=os.environ.get("ACME_ACCOUNT_URI"),
    )
    return ctx.to_dict()


# Activity — answer challenges, poll, finalize, return PFX
@app.activity_trigger(input_name="input")
def finalize_acme_order(input: dict) -> dict:
    order_context = AcmeOrderContext.from_dict(input["order_context"])
    pfx_bytes = complete_order(order_context)
    return {
        "cert_name": input["cert_name"],
        "pfx_b64": b64encode(pfx_bytes).decode(),
    }


# Activity — create DNS TXT record for ACME challenge
@app.activity_trigger(input_name="input")
def create_dns_txt_record(input: dict) -> None:
    config = load_config()
    with get_dns_provider(config, provider_name=input["dns_provider"]) as provider:
        zone, relative = split_record_name(input["record_name"], input["domain"])
        provider.create_txt_record(zone, relative, input["record_value"])


# Activity — delete DNS TXT record after ACME validation
@app.activity_trigger(input_name="input")
def delete_dns_txt_record(input: dict) -> None:
    config = load_config()
    with get_dns_provider(config, provider_name=input["dns_provider"]) as provider:
        zone, relative = split_record_name(input["record_name"], input["domain"])
        provider.delete_txt_record(zone, relative)
