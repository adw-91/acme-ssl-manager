"""Azure Functions entry point — triggers and activity function definitions."""

import logging
from base64 import b64decode

import azure.durable_functions as df
import azure.functions as func

from cert_manager.config import load_config
from cert_manager.keyvault import scan_certificates, upload_certificate

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
