# Instance ID Header Injection Policy

This policy injects an `x-anypoint-api-instance-id` header with the API instance ID value at the beginning of message processing. The header is added to all incoming requests before they are forwarded to the backend service.

## Overview

The policy automatically retrieves the API instance ID from the Flex Gateway metadata and adds it as a header to every incoming request. This is useful for:
- Request tracing and correlation across multiple API instances
- Debugging and monitoring in multi-instance deployments
- Backend services that need to identify which API instance processed the request
- **Agent Network Integration**: You can apply this policy within the `agent-network.yaml` to the agent connections in order to have the agent egress entry injecting the API Instance ID. This may be useful in case the agent is using an MCP server and you want to visualize the interaction in the Agent Visualizer.

## Use Case: Agent Visualizer for Standalone Agent → MCP Server Interactions

Use this policy to surface Agent ↔ MCP Server interactions in **Agent Visualizer** even when the agent is **not part of an Agent Network**.

Assume an ERP Agent connecting to two MCP Servers (`ERP Order MCP Server` and `ERP Inventory MCP Server`):

1. **Protect both MCP Servers under egress** in API Manager.
   - Add the `Agent Connection Telemetry` policy on each MCP Server.
2. **Protect the ERP Agent under ingress** in API Manager.
   - The ingress entry's **Instance ID** (visible under *Agent and Tool Instances → ERP Agent*) is the value Agent Visualizer uses to correlate calls back to the agent.
3. **In the ERP Agent, when calling any MCP Server**:
   - Use the MCP Server's egress **Consumer Endpoint**.
   - Add the request header `x-anypoint-api-instance-id` with the **ERP Agent's ingress Instance ID** as the value (e.g. `20574180`).

This policy automates step 3 when applied to the agent's ingress: it injects `x-anypoint-api-instance-id` with the agent's API instance ID on every outbound call routed through the gateway, so Agent Visualizer can stitch the agent into the MCP interaction graph without requiring an Agent Network definition.

## How it Works

1. The policy intercepts incoming requests during the request phase
2. Extracts the API instance ID from the gateway metadata (`metadata.api_metadata.id`)
3. Injects the `x-anypoint-api-instance-id` header with the instance ID value
4. If no instance ID is available in metadata, uses "default-instance-id" as fallback
5. Logs the injection for monitoring purposes

## Configuration

This policy requires **no configuration parameters**. It works out-of-the-box without any setup.

## Header Details

- **Header Name**: `x-anypoint-api-instance-id`
- **Header Value**: The actual API instance ID from Flex Gateway metadata
- **Fallback Value**: `default-instance-id` (when metadata is unavailable)

## Project Structure

This is a split-model PDK policy with two subprojects:

```
instance-id-header-injection/
  instance-id-header-injection-definition/   # Policy schema, Exchange metadata
  instance-id-header-injection-flex/         # Rust/WASM implementation
```

- **Definition** (`gcl.yaml`, `exchange.json`) — defines the policy's (empty) configuration schema and Exchange asset metadata.
- **Implementation** (`src/lib.rs`) — Rust code compiled to WASM, executed by Flex Gateway's Envoy runtime.

## Version Information

- **Policy Version**: 1.1.0
- **PDK Version**: 1.8.0
- **Rust Version**: 1.88.0
- **Rust Edition**: 2018

This policy was created with the Flex Gateway Policy Development Kit (PDK). To find the complete PDK documentation, see [PDK Overview](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview) on the Mulesoft documentation site.
