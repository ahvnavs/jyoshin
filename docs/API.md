openapi: 3.0.3
info:
  title: Jyōshin Server Truth Engine API
  description: Local-first, read-only system truth inspection API for Linux.
  version: 0.1.0-dev
  license:
    name: Apache 2.0
    url: https://www.apache.org/licenses/LICENSE-2.0.html
servers:
  - url: http://127.0.0.1:7777
    description: Localhost API server
paths:
  /api/v1/health:
    get:
      summary: Health check endpoint
      responses:
        '200':
          description: Server healthy
  /api/v1/version:
    get:
      summary: Binary and build version metadata
      responses:
        '200':
          description: Version info
  /api/v1/verdict:
    get:
      summary: Server health verdict and Chaos Index (0-100)
      responses:
        '200':
          description: Verdict summary
  /api/v1/stream:
    get:
      summary: Server-Sent Events (SSE) real-time verdict stream
      responses:
        '200':
          description: Event stream (text/event-stream)
  /api/v1/findings:
    get:
      summary: List all evaluated rule findings
      responses:
        '200':
          description: Array of findings
  /api/v1/changes:
    get:
      summary: Diff between two snapshots
      parameters:
        - name: from
          in: query
          schema:
            type: string
        - name: to
          in: query
          schema:
            type: string
      responses:
        '200':
          description: Semantic ChangeSet
  /api/v1/forecasts:
    get:
      summary: Statistical time-to-exhaustion forecasts
      responses:
        '200':
          description: Resource forecasts
  /api/v1/blastradius/{id}:
    get:
      summary: Calculate blast radius and outages for a node
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Blast radius report
  /api/v1/dependencies:
    get:
      summary: Inbound and outbound dependency map
      responses:
        '200':
          description: Topology map
  /api/v1/decommission:
    get:
      summary: Decommission readiness evaluation
      responses:
        '200':
          description: Decommission report
  /api/v1/migration:
    get:
      summary: Migration inventory plan (configs, data, ports, secret paths)
      responses:
        '200':
          description: Migration plan
  /api/v1/report:
    get:
      summary: Generate State of this Server report
      parameters:
        - name: format
          in: query
          schema:
            type: string
            enum: [html, json, md]
      responses:
        '200':
          description: Rendered report

