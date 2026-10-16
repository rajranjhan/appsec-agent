"""Explicit provider configuration; credentials never enter prompts or reports."""

from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import Field, SecretStr, model_validator
from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APPSEC_", extra="ignore")
    provider: Literal["openai", "anthropic"] = "openai"
    model: str = Field(min_length=1, max_length=200)
    api_key: SecretStr
    base_url: str | None = None
    allowed_hosts: frozenset[str] = frozenset({"api.openai.com", "api.anthropic.com"})

    @model_validator(mode="after")
    def validate_endpoint(self) -> "Settings":
        if not self.api_key.get_secret_value().strip():
            raise ValueError("APPSEC_API_KEY must not be empty")
        if self.base_url:
            url = urlsplit(self.base_url)
            if (
                url.scheme != "https"
                or url.hostname not in self.allowed_hosts
                or url.username
                or url.password
                or url.query
                or url.fragment
                or url.port not in {None, 443}
            ):
                raise ValueError(
                    "Provider endpoint requires HTTPS on port 443 and an explicitly allowed host"
                )
            if self.provider != "openai":
                raise ValueError(
                    "Custom endpoints currently support OpenAI-compatible providers only"
                )
        return self

    def make_model(self, client: httpx.AsyncClient) -> Model:
        key = self.api_key.get_secret_value()
        if self.provider == "anthropic":
            return AnthropicModel(
                self.model, provider=AnthropicProvider(api_key=key, http_client=client)
            )
        return OpenAIChatModel(
            self.model,
            provider=OpenAIProvider(
                api_key=key,
                base_url=self.base_url or "https://api.openai.com/v1",
                http_client=client,
            ),
        )
