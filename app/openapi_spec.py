from __future__ import annotations

import json
from collections import OrderedDict
from typing import Any

import yaml


def build_openapi_spec() -> dict[str, Any]:
    spec: OrderedDict[str, Any] = OrderedDict(
        [
            ("openapi", "3.0.3"),
            (
                "info",
                {
                    "title": "IOC Service API",
                    "version": "1.9.2",
                    "description": "Supported versioned API surface for IOC Service.",
                },
            ),
            ("servers", [{"url": "/"}]),
            (
                "externalDocs",
                {
                    "description": "Human-readable API and migration documentation",
                    "url": "/docs/api",
                },
            ),
            (
                "paths",
                OrderedDict(
                    [
                        (
                            "/api/v1/indicators",
                            {
                                "get": {
                                    "summary": "List indicators as JSON",
                                    "parameters": [
                                        {"in": "query", "name": "q", "schema": {"type": "string"}, "description": "Kibana-style search query (e.g. type:ip AND confidence:>70)"},
                                        {"in": "query", "name": "type", "schema": {"type": "string", "default": "all"}, "description": "IOC type filter (ip, domain, url, hash, email, all)"},
                                        {"in": "query", "name": "tlp", "schema": {"type": "string", "default": "all"}, "description": "TLP classification filter"},
                                        {"in": "query", "name": "source", "schema": {"type": "string", "default": "all"}, "description": "Feed source filter"},
                                        {"in": "query", "name": "min_conf", "schema": {"type": "integer", "minimum": 0, "maximum": 100}, "description": "Minimum confidence score"},
                                        {"in": "query", "name": "max_conf", "schema": {"type": "integer", "minimum": 0, "maximum": 100}, "description": "Maximum confidence score"},
                                        {"in": "query", "name": "since", "schema": {"type": "string", "enum": ["30m","1h","6h","12h","24h","7d","30d","2m","3m","6m","1y","all"], "default": "all"}, "description": "Relative time window — filters on last_seen >= now - period"},
                                        {"in": "query", "name": "date_from", "schema": {"type": "string", "format": "date"}, "description": "Absolute start date for last_seen filter (YYYY-MM-DD)"},
                                        {"in": "query", "name": "date_to", "schema": {"type": "string", "format": "date"}, "description": "Absolute end date for last_seen filter (YYYY-MM-DD)"},
                                        {"in": "query", "name": "limit", "schema": {"type": "integer", "minimum": 1}, "description": "Page size"},
                                        {"in": "query", "name": "offset", "schema": {"type": "integer", "minimum": 0}, "description": "Page offset"},
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Indicators list",
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "count": {"type": "integer"},
                                                            "total": {"type": "integer"},
                                                            "limit": {"type": "integer"},
                                                            "offset": {"type": "integer"},
                                                            "filters": {"type": "object"},
                                                            "items": {"type": "array", "items": {"$ref": "#/components/schemas/Indicator"}},
                                                        },
                                                    }
                                                }
                                            },
                                        },
                                        "400": {"$ref": "#/components/responses/Error"},
                                    },
                                }
                            },
                        ),
                        (
                            "/api/v1/sync",
                            {
                                "post": {
                                    "summary": "Enqueue a feed sync job",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "source": {
                                                            "type": "string",
                                                            "description": "Feed source id or `all`",
                                                        }
                                                    },
                                                    "required": ["source"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "202": {
                                            "description": "Sync job(s) accepted",
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "source": {"type": "string"},
                                                            "jobs": {
                                                                "type": "array",
                                                                "items": {
                                                                    "type": "object",
                                                                    "properties": {
                                                                        "feed_source_id": {"type": "string"},
                                                                        "job_id": {"type": "string"},
                                                                        "created": {"type": "boolean"},
                                                                    },
                                                                },
                                                            },
                                                            "blocked": {"type": "array", "items": {"type": "string"}},
                                                        },
                                                    }
                                                }
                                            },
                                        },
                                        "400": {"$ref": "#/components/responses/Error"},
                                    },
                                }
                            },
                        ),
                        (
                            "/api/v1/feeds",
                            {
                                "get": {
                                    "summary": "List feed operational state",
                                    "parameters": [
                                        {"in": "query", "name": "limit", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25}},
                                        {"in": "query", "name": "offset", "schema": {"type": "integer", "minimum": 0, "default": 0}},
                                        {"in": "query", "name": "sort", "schema": {"type": "string", "default": "source"}},
                                        {"in": "query", "name": "order", "schema": {"type": "string", "enum": ["asc", "desc"], "default": "asc"}},
                                        {"in": "query", "name": "status", "schema": {"type": "string", "default": "all"}},
                                        {"in": "query", "name": "datasource", "schema": {"type": "string", "default": "all"}},
                                        {"in": "query", "name": "configured", "schema": {"type": "string", "default": "all"}},
                                        {"in": "query", "name": "q", "schema": {"type": "string"}},
                                        {"in": "query", "name": "problems_only", "schema": {"type": "boolean", "default": False}},
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Feed inventory and state",
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "items": {"type": "array", "items": {"type": "object"}},
                                                            "total": {"type": "integer"},
                                                            "limit": {"type": "integer"},
                                                            "offset": {"type": "integer"},
                                                            "sort": {"type": "string"},
                                                            "order": {"type": "string"},
                                                            "filters": {"type": "object"},
                                                        },
                                                    }
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        ),
                        (
                            "/api/v1/feeds/metrics",
                            {
                                "get": {
                                    "summary": "Return feed operational metrics for a time window",
                                    "parameters": [
                                        {"in": "query", "name": "window", "schema": {"type": "string", "example": "24h"}},
                                        {"in": "query", "name": "hours", "schema": {"type": "integer"}},
                                        {"in": "query", "name": "datasource", "schema": {"type": "string", "default": "all"}},
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Feed metrics",
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "window": {"type": "string"},
                                                            "hours": {"type": "integer"},
                                                            "bucket": {"type": "string"},
                                                            "datasource": {"type": "string"},
                                                            "total_feeds": {"type": "integer"},
                                                            "items": {"type": "array", "items": {"type": "object"}},
                                                            "timeseries": {"type": "array", "items": {"type": "object"}},
                                                            "summary": {"type": "object"},
                                                        },
                                                    }
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        ),
                        (
                            "/api/v1/runs/current",
                            {
                                "get": {
                                    "summary": "Return queue and run state",
                                    "responses": {
                                        "200": {
                                            "description": "Current scheduler, queue, and run state",
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "scheduler_heartbeat": {"type": "string"},
                                                            "active_run_id": {"type": "string", "nullable": True},
                                                            "active_job_id": {"type": "string", "nullable": True},
                                                            "queued_jobs": {"type": "array", "items": {"type": "object"}},
                                                            "running": {"type": "array", "items": {"type": "object"}},
                                                            "latest": {"type": "array", "items": {"type": "object"}},
                                                        },
                                                    }
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        ),
                        (
                            "/api/v1/logs",
                            {
                                "get": {
                                    "summary": "Query application logs",
                                    "parameters": [
                                        {"in": "query", "name": "feed", "schema": {"type": "string"}},
                                        {"in": "query", "name": "job_id", "schema": {"type": "string"}},
                                        {"in": "query", "name": "run_id", "schema": {"type": "string"}},
                                        {"in": "query", "name": "level", "schema": {"type": "string"}},
                                        {"in": "query", "name": "component", "schema": {"type": "string"}},
                                        {"in": "query", "name": "since", "schema": {"type": "string", "format": "date-time"}},
                                        {"in": "query", "name": "until", "schema": {"type": "string", "format": "date-time"}},
                                        {"in": "query", "name": "limit", "schema": {"type": "integer", "minimum": 1, "maximum": 500, "default": 200}},
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Log query results",
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "count": {"type": "integer"},
                                                            "items": {
                                                                "type": "array",
                                                                "items": {
                                                                    "type": "object",
                                                                    "properties": {
                                                                        "created_at": {"type": "string"},
                                                                        "level": {"type": "string"},
                                                                        "component": {"type": "string"},
                                                                        "message": {"type": "string"},
                                                                        "feed_source_id": {"type": "string", "nullable": True},
                                                                        "run_id": {"type": "string", "nullable": True},
                                                                        "metadata": {"type": "object"},
                                                                    },
                                                                },
                                                            },
                                                        },
                                                    }
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        ),
                    ]
                ),
            ),
            (
                "components",
                {
                    "schemas": {
                        "Indicator": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "integer"},
                                "uuid": {"type": "string"},
                                "value": {"type": "string"},
                                "type": {"type": "string"},
                                "source": {"type": "string"},
                                "source_id": {"type": "string", "nullable": True},
                                "confidence": {"type": "integer"},
                                "tlp": {"type": "string"},
                                "is_active": {"type": "boolean"},
                                "tags": {"type": "array", "items": {"type": "string"}},
                                "metadata": {"type": "object"},
                                "first_seen": {"type": "string", "nullable": True},
                                "last_seen": {"type": "string", "nullable": True},
                            },
                        }
                    },
                    "responses": {
                        "Error": {
                            "description": "Validation or request error",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "error": {"type": "string"},
                                            "correlation_id": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
            ),
        ]
    )
    return json.loads(json.dumps(spec))


def render_openapi_json() -> str:
    return json.dumps(build_openapi_spec(), indent=2, sort_keys=False) + "\n"


def render_openapi_yaml() -> str:
    return yaml.safe_dump(build_openapi_spec(), sort_keys=False, allow_unicode=False)
